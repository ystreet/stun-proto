// Copyright (C) 2026 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! STUN authentication

use core::net::SocketAddr;
use core::ops::Deref;
use core::time::Duration;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use stun_types::attribute::{
    pad_attribute_len, ErrorCode, MessageIntegrity, MessageIntegritySha256, Nonce,
    PasswordAlgorithm, PasswordAlgorithmValue, PasswordAlgorithms, Realm, Userhash, Username,
};
use stun_types::message::{
    IntegrityAlgorithm, IntegrityKey, LongTermCredentials, Message, MessageClass,
    ShortTermCredentials, StunParseError, StunWriteError, ValidateError,
};
use stun_types::prelude::{
    Attribute, AttributeExt, AttributeFromRaw, AttributeStaticType, MessageWrite, MessageWriteExt,
};

use sans_io_time::Instant;
use tracing::{debug, trace, warn};

use base64::prelude::*;
use hashbrown::HashMap;
use siphasher::sip::SipHasher;

/// Authentication for short term credentials.
#[derive(Debug, Default)]
pub struct ShortTermAuth {
    credentials: Option<(ShortTermCredentials, IntegrityAlgorithm, IntegrityKey)>,
    signature_bytes: usize,
}

impl ShortTermAuth {
    /// Construct an authentication method for short term credential handling.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set the credentials that all messages should be signed with.
    pub fn set_credentials(
        &mut self,
        credentials: ShortTermCredentials,
        algorithm: IntegrityAlgorithm,
    ) {
        let key = credentials.make_key();
        self.credentials = Some((credentials, algorithm, key));
        self.signature_bytes = bytes_for_integrity(algorithm);
    }

    /// The credentials that all messages should be signed with.
    pub fn credentials(&self) -> Option<(&ShortTermCredentials, IntegrityAlgorithm)> {
        self.credentials
            .as_ref()
            .map(|(creds, algo, _key)| (creds, *algo))
    }

    /// The local integrity key that all messages should be signed with.
    pub fn integrity_key(&self) -> Option<&IntegrityKey> {
        self.credentials.as_ref().map(|(_creds, _algo, key)| key)
    }

    /// Number of bytes required to successfully add message integrity to an outgoing message.
    pub fn message_signature_bytes(&self) -> usize {
        self.signature_bytes
    }
    /// Sign an outgoing STUN message.
    #[tracing::instrument(skip(self, msg), err(Debug))]
    pub fn sign_outgoing_message<W: MessageWrite>(
        &mut self,
        mut msg: W,
    ) -> Result<W, StunWriteError> {
        if let Some((_creds, algo, key)) = self.credentials.as_ref() {
            msg.add_message_integrity_with_key(key, *algo)?;
            Ok(msg)
        } else {
            Ok(msg)
        }
    }

    /// Validate an incoming message according to the rules of the STUN short term credentials
    /// mechanism.
    #[tracing::instrument(skip(self, msg), err(Debug))]
    pub fn validate_incoming_message(
        &mut self,
        msg: &Message<'_>,
    ) -> Result<Option<IntegrityAlgorithm>, ValidateError> {
        let Some((_creds, _algo, key)) = self.credentials.as_ref() else {
            return Ok(None);
        };
        msg.validate_integrity_with_key(key).map(Some)
    }
}

fn bytes_for_integrity(integrity: IntegrityAlgorithm) -> usize {
    match integrity {
        IntegrityAlgorithm::Sha1 => 24,
        IntegrityAlgorithm::Sha256 => 36,
    }
}

/// Possible results on authentication validation.
#[derive(Debug)]
pub enum LongTermValidation {
    /// The request should be re-signed and resent as some authentication parameters have changed.
    ResendRequest(Option<IntegrityAlgorithm>),
    /// The STUN message has been validated (possibly) with the algorithm.
    Validated(IntegrityAlgorithm),
}

/// Errors that can occur during an authentication flow.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum AuthErrorReason {
    /// Parsing error of the message.
    #[error("{}", .0)]
    Parse(StunParseError),
    /// The request is malformed in some way.
    #[error("The request is malformed in some way")]
    BadRequest,
    /// The nonce provided is out of date and must be updated.
    #[error("The provided nonce is out of date and must be updated")]
    StaleNonce,
    /// The message is not sufficiently authenticated.
    #[error("The message is not sufficiently authenticated")]
    Unauthorized,
    /// Message failed integrity checks.
    #[error("The message failed integrity checks")]
    IntegrityFailed,
    /// A required feature is not supported.
    #[error("A required feature is not supported")]
    UnsupportedFeature,
}

impl From<ValidateError> for AuthErrorReason {
    fn from(value: ValidateError) -> Self {
        match value {
            ValidateError::Parse(e) => Self::Parse(e),
            ValidateError::IntegrityFailed => Self::IntegrityFailed,
        }
    }
}

/// Errors that can occur during an authentication flow.
#[derive(Debug)]
pub struct AuthError {
    reason: AuthErrorReason,
    integrity: Option<IntegrityAlgorithm>,
}

impl AuthError {
    /// The reason for the authentication error.
    pub fn reason(&self) -> AuthErrorReason {
        self.reason
    }
    /// Any validated integrity that was present on the offending message.
    pub fn integrity(&self) -> Option<IntegrityAlgorithm> {
        self.integrity
    }
}

impl From<StunParseError> for AuthErrorReason {
    fn from(value: StunParseError) -> Self {
        Self::Parse(value)
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum User {
    Name(String),
    Hash([u8; 32]),
}

#[derive(Debug)]
struct RequestAuth {
    user: User,
    realm: String,
    nonce: String,
    password_algos: smallvec::SmallVec<[PasswordAlgorithmValue; 2]>,
    key: IntegrityKey,
    algo: IntegrityAlgorithm,
}

#[derive(Debug, Default)]
enum AuthState {
    #[default]
    Initial,
    Authenticating(RequestAuth),
    Authenticated(RequestAuth),
}

impl AuthState {
    fn auth(&self) -> Option<&RequestAuth> {
        match self {
            Self::Initial => None,
            Self::Authenticating(auth) => Some(auth),
            Self::Authenticated(auth) => Some(auth),
        }
    }

    fn as_authenticated(&mut self) {
        let mut old = Self::Initial;
        core::mem::swap(&mut old, self);
        *self = match old {
            Self::Initial => Self::Initial,
            Self::Authenticating(auth) | Self::Authenticated(auth) => Self::Authenticated(auth),
        };
    }

    fn replace_nonce(&mut self, new_nonce: String, new_realm: String) {
        match self {
            Self::Initial => (),
            Self::Authenticating(auth) => {
                auth.nonce = new_nonce;
                auth.realm = new_realm;
            }
            Self::Authenticated(auth) => {
                auth.nonce = new_nonce;
                auth.realm = new_realm;
            }
        }
    }
}

/// A feature.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Feature {
    /// The configuration will automatically be used when supported.
    #[default]
    Auto,
    /// The configuration is enabled and required.
    Required,
    /// The configuration is disabled and will not be used.
    Disabled,
}

impl Feature {
    /// Whether to try using the feature.
    fn possible(&self) -> bool {
        matches!(self, Self::Auto | Self::Required)
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
struct NonceSecurityBits {
    bytes: [u8; 3],
}

impl NonceSecurityBits {
    fn required(&self) -> bool {
        self.bytes[0] != 0 || self.bytes[1] != 0 || self.bytes[2] != 0
    }

    fn from_nonce(bytes: &str) -> Option<Self> {
        if !bytes.starts_with(LONG_TERM_RFC8489_NONCE_COOKIE) {
            return None;
        }
        let security = &bytes[LONG_TERM_RFC8489_NONCE_COOKIE.len()..];
        if security.len() < 4 {
            return None;
        }
        let mut bytes = [0; 3];
        let len = BASE64_STANDARD
            .decode_slice(&security[..4], &mut bytes)
            .ok()?;
        if len != 3 {
            return None;
        }
        Some(Self { bytes })
    }

    fn as_string(&self) -> String {
        let mut ret = String::with_capacity(LONG_TERM_RFC8489_NONCE_COOKIE.len() + 4);
        ret.push_str(LONG_TERM_RFC8489_NONCE_COOKIE);
        BASE64_STANDARD.encode_string(self.bytes, &mut ret);
        ret
    }

    fn password_algorithms(&self) -> bool {
        (self.bytes[0] & 0x80) != 0
    }

    fn set_password_algorithms(&mut self, password_algorithms: bool) {
        if password_algorithms {
            self.bytes[0] |= 0x80;
        } else {
            self.bytes[0] &= !0x80;
        }
    }

    fn username_anonymity(&self) -> bool {
        (self.bytes[0] & 0x40) != 0
    }

    fn set_username_anonymity(&mut self, username_anonymity: bool) {
        if username_anonymity {
            self.bytes[0] |= 0x40;
        } else {
            self.bytes[0] &= !0x40;
        }
    }
}

/// Authentication for long term credentials.
#[derive(Debug)]
pub struct LongTermClientAuth {
    credentials: Option<LongTermCredentials>,
    auth: AuthState,
    signature_bytes: usize,
    supported_integrity: smallvec::SmallVec<[IntegrityAlgorithm; 2]>,
    anonymous_username: Feature,
}

impl Default for LongTermClientAuth {
    fn default() -> Self {
        Self {
            credentials: None,
            auth: AuthState::Initial,
            signature_bytes: 0,
            supported_integrity: smallvec::SmallVec::from_iter([IntegrityAlgorithm::Sha1]),
            anonymous_username: Feature::default(),
        }
    }
}

impl LongTermClientAuth {
    /// Construct an authentication method for long term credential handling for a client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the local credentials that all messages should be signed with
    pub fn set_credentials(&mut self, credentials: LongTermCredentials) {
        self.credentials = Some(credentials);
    }

    /// The credentials that all messages should be signed with
    pub fn credentials(&self) -> Option<&LongTermCredentials> {
        self.credentials.as_ref()
    }

    /// The supported integrity algorithms used.
    pub fn supported_integrity(&self) -> &[IntegrityAlgorithm] {
        &self.supported_integrity
    }

    /// Add a supported integrity algorithms that will be used.
    pub fn add_supported_integrity(&mut self, integrity: IntegrityAlgorithm) {
        if !self.supported_integrity.contains(&integrity) {
            self.supported_integrity.push(integrity);
        }
    }

    /// Set the supported integrity algorithm used.
    pub fn set_supported_integrity(&mut self, integrity: IntegrityAlgorithm) {
        self.supported_integrity = smallvec::SmallVec::from_iter([integrity]);
    }

    /// Set whether anonymous username usage is required.
    ///
    /// A value of `true` requires the server to support RFC 8489 and the [`Userhash`] attribute.
    pub fn set_anonymous_username(&mut self, anonymous: Feature) {
        self.anonymous_username = anonymous;
    }

    /// Whether anonymous username usage is required.
    ///
    /// A value of true requires the server to support RFC 8489 and the [`Userhash`] attribute.
    pub fn anonymous_username(&mut self) -> Feature {
        self.anonymous_username
    }

    /// Number of bytes required to successfully add message integrity to an outgoing message.
    pub fn message_signature_bytes(&self) -> usize {
        self.signature_bytes
    }

    /// Sign an outgoing STUN message.
    #[tracing::instrument(name = "client_sign_outgoing_message", skip(self, msg), err(Debug))]
    pub fn sign_outgoing_message<W: MessageWrite>(
        &mut self,
        mut msg: W,
    ) -> Result<W, StunWriteError> {
        if let Some(auth) = self.auth.auth() {
            if msg.has_class(MessageClass::Request) {
                msg.add_attribute(&Nonce::new(&auth.nonce)?)?;
                msg.add_attribute(&Realm::new(&auth.realm)?)?;
                match &auth.user {
                    User::Name(name) => msg.add_attribute(&Username::new(name)?)?,
                    User::Hash(hash) => msg.add_attribute(&Userhash::new(*hash))?,
                }
            }
            if !auth.password_algos.is_empty() {
                msg.add_attribute(&PasswordAlgorithms::new(&auth.password_algos))?;
            }
            if auth.algo != IntegrityAlgorithm::Sha1 || !auth.password_algos.is_empty() {
                msg.add_attribute(&PasswordAlgorithm::new(match auth.algo {
                    IntegrityAlgorithm::Sha1 => PasswordAlgorithmValue::MD5,
                    IntegrityAlgorithm::Sha256 => PasswordAlgorithmValue::SHA256,
                }))?;
            }
            msg.add_message_integrity_with_key(&auth.key, auth.algo)?;
            Ok(msg)
        } else {
            Ok(msg)
        }
    }

    /// Validate an incoming message according to the rules of the STUN long term credentials
    /// mechanism for clients.
    #[tracing::instrument(name = "client_validate_incoming_message", skip(self, msg), err(Debug))]
    pub fn validate_incoming_message(
        &mut self,
        msg: &Message<'_>,
    ) -> Result<LongTermValidation, AuthError> {
        let ret = if let Some(auth) = self.auth.auth() {
            msg.validate_integrity_with_key(&auth.key)
                .map_err(|e| match e {
                    ValidateError::IntegrityFailed
                    | ValidateError::Parse(StunParseError::MissingAttribute(
                        MessageIntegrity::TYPE | MessageIntegritySha256::TYPE,
                    )) => ValidateError::IntegrityFailed,
                    e => e,
                })
        } else {
            Err(ValidateError::IntegrityFailed)
        };
        if msg.is_response() {
            if msg.has_class(MessageClass::Error) {
                let mut realm = None;
                let mut nonce = None;
                let mut error_code = Err(StunParseError::MissingAttribute(ErrorCode::TYPE));
                let mut password_algos = None;
                for (_offset, attr) in msg.iter_attributes() {
                    match attr.get_type() {
                        Realm::TYPE => realm = Realm::from_raw(attr).ok(),
                        Nonce::TYPE => nonce = Nonce::from_raw(attr).ok(),
                        ErrorCode::TYPE => error_code = ErrorCode::from_raw(attr),
                        PasswordAlgorithms::TYPE => {
                            password_algos = PasswordAlgorithms::from_raw(attr).ok()
                        }
                        _ => (),
                    }
                }
                if let Ok(error_code) = error_code {
                    match error_code.code() {
                        ErrorCode::UNAUTHORIZED
                            if !matches!(self.auth, AuthState::Authenticated(_)) =>
                        {
                            if let Some(((realm, nonce), credentials)) =
                                realm.zip(nonce).zip(self.credentials.as_ref())
                            {
                                if let AuthState::Authenticating(auth) = &self.auth {
                                    // credentials are not changing so therefore must be wrong for
                                    // accessing this server.
                                    if auth.realm == realm.realm() && auth.nonce == nonce.nonce() {
                                        return Err(AuthError {
                                            reason: AuthErrorReason::Unauthorized,
                                            integrity: None,
                                        });
                                    }
                                }
                                let (algo, anon) = if let Some(security) =
                                    NonceSecurityBits::from_nonce(nonce.nonce())
                                {
                                    let algo = if let Some(password_algos) = password_algos.as_ref()
                                    {
                                        let Some(algo) = password_algos
                                            .algorithms()
                                            .iter()
                                            .map(|algo| algo.as_integrity())
                                            .find(|algo| self.supported_integrity.contains(algo))
                                        else {
                                            trace!("No compatible password algorithms supported");
                                            return Err(AuthError {
                                                reason: AuthErrorReason::UnsupportedFeature,
                                                integrity: None,
                                            });
                                        };
                                        algo
                                    } else if security.password_algorithms() {
                                        trace!("nonce indicates password algorithms attribute that does not exist on message");
                                        return Err(AuthError {
                                            reason: AuthErrorReason::Unauthorized,
                                            integrity: None,
                                        });
                                    } else {
                                        IntegrityAlgorithm::Sha1
                                    };
                                    (
                                        algo,
                                        security.username_anonymity()
                                            && self.anonymous_username.possible(),
                                    )
                                } else {
                                    if matches!(self.anonymous_username, Feature::Required) {
                                        trace!("nonce does not support anonymous username");
                                        return Err(AuthError {
                                            reason: AuthErrorReason::UnsupportedFeature,
                                            integrity: None,
                                        });
                                    }
                                    if !self.supported_integrity.contains(&IntegrityAlgorithm::Sha1)
                                    {
                                        trace!("nonce does not support integrity other than Sha1");
                                        return Err(AuthError {
                                            reason: AuthErrorReason::UnsupportedFeature,
                                            integrity: None,
                                        });
                                    }
                                    (IntegrityAlgorithm::Sha1, false)
                                };
                                self.signature_bytes = nonce.padded_len()
                                    + realm.padded_len()
                                    + bytes_for_integrity(algo);
                                let realm = realm.realm().to_string();
                                let key = credentials.to_key(realm.clone()).make_key(algo);
                                let username = credentials.username();
                                let user = if anon {
                                    User::Hash(Userhash::compute(username, &realm))
                                } else {
                                    User::Name(username.to_string())
                                };
                                let password_algos = if let Some(algos) = password_algos {
                                    smallvec::SmallVec::from_slice(algos.algorithms())
                                } else {
                                    smallvec::SmallVec::new()
                                };
                                self.auth = AuthState::Authenticating(RequestAuth {
                                    user,
                                    realm,
                                    nonce: nonce.nonce().to_string(),
                                    password_algos,
                                    key,
                                    algo,
                                });

                                trace!("retry request as credentials have changed");
                                return Ok(LongTermValidation::ResendRequest(ret.ok()));
                            } else {
                                // possible DoS?
                                return Err(AuthError {
                                    reason: AuthErrorReason::Unauthorized,
                                    integrity: None,
                                });
                            }
                        }
                        ErrorCode::STALE_NONCE => {
                            if let Some((new_nonce, new_realm)) = is_valid_stale_nonce(msg) {
                                self.auth.replace_nonce(
                                    new_nonce.nonce().to_string(),
                                    new_realm.realm().to_string(),
                                );
                                self.signature_bytes = 4
                                    + pad_attribute_len(new_nonce.padded_len())
                                    + 4
                                    + pad_attribute_len(new_realm.padded_len())
                                    + self
                                        .auth
                                        .auth()
                                        .map(|auth| bytes_for_integrity(auth.algo))
                                        .unwrap_or_default();
                                return Ok(LongTermValidation::ResendRequest(ret.ok()));
                            }
                        }
                        _ => (),
                    };
                    return ret
                        .map(LongTermValidation::Validated)
                        .map_err(|e| AuthError {
                            reason: e.into(),
                            integrity: None,
                        });
                }
            } else if msg.has_class(MessageClass::Success) && ret.is_ok() {
                self.auth.as_authenticated();
            }
        }
        ret.map(LongTermValidation::Validated)
            .map_err(|e| AuthError {
                reason: e.into(),
                integrity: None,
            })
    }
}

#[derive(Debug)]
struct ClientNonce {
    expires_at: Instant,
    value: String,
    password_algorithms: smallvec::SmallVec<[PasswordAlgorithmValue; 2]>,
}

#[derive(Debug)]
struct ClientAuth {
    credentials: LongTermCredentials,
    keys: HashMap<IntegrityAlgorithm, IntegrityKey, RandomState>,
}

/// A value prepended to a Nonce to indicate support for RFC 8489.
///
/// Usage of this value is required to support:
///  - [`IntegrityAlgorithm`]s other than Sha1.
///  - Anonymous usernames.
pub static LONG_TERM_RFC8489_NONCE_COOKIE: &str = "obMatJos2";

static MINIMUM_NONCE_EXPIRY_DURATION: Duration = Duration::from_secs(30);
static DEFAULT_NONCE_EXPIRY_DURATION: Duration = Duration::from_secs(3600);

/// Authentication for long term credentials.
#[derive(Debug)]
pub struct LongTermServerAuth {
    realm: String,
    user_hash: HashMap<[u8; 32], String, RandomState>,
    users: HashMap<String, ClientAuth, RandomState>,
    nonces: LongTermNonce,
    // remote address -> username + IntegrityAlgorithm
    clients: BTreeMap<SocketAddr, (String, IntegrityAlgorithm)>,
    backup_integrity: HashMap<IntegrityAlgorithm, IntegrityKey, RandomState>,
}

#[derive(Debug)]
struct LongTermNonce {
    generate_config: NonceConfiguration,
    nonce_expiry_duration: Duration,
    nonces: HashMap<SocketAddr, ClientNonce, RandomState>,
}

#[derive(Debug)]
struct NonceConfiguration {
    supported_integrity: smallvec::SmallVec<[IntegrityAlgorithm; 2]>,
    anonymous_username: Feature,
}

impl NonceConfiguration {
    fn generate_random_nonce_string() -> String {
        #[cfg(not(feature = "std"))]
        {
            use rand::Rng;
            use rand::TryRngCore;
            let mut rng = rand::rngs::OsRng.unwrap_err();
            String::from_iter((0..16).map(|_| rng.sample(rand::distr::Alphanumeric) as char))
        }
        #[cfg(feature = "std")]
        {
            use rand::Rng;
            let mut rng = rand::rng();
            String::from_iter((0..16).map(|_| rng.sample(rand::distr::Alphanumeric) as char))
        }
    }

    fn generate_nonce(&self) -> String {
        let random_string = Self::generate_random_nonce_string();
        let mut security = NonceSecurityBits::default();
        if self
            .supported_integrity
            .iter()
            .any(|&algo| algo != IntegrityAlgorithm::Sha1)
        {
            security.set_password_algorithms(true);
        }
        if self.anonymous_username.possible() {
            security.set_username_anonymity(true);
        }
        if security.required() {
            let mut ret = security.as_string();
            ret.push_str(&random_string);
            ret
        } else {
            random_string
        }
    }
}

impl LongTermNonce {
    fn validate_nonce(&mut self, from: SocketAddr, now: Instant) -> &mut ClientNonce {
        let nonce_expiry_duration = self.nonce_expiry_duration;
        let nonce_data = self.nonces.entry(from).or_insert_with(|| ClientNonce {
            expires_at: now + self.nonce_expiry_duration,
            value: self.generate_config.generate_nonce(),
            password_algorithms: smallvec::SmallVec::new(),
        });
        if nonce_data.expires_at < now {
            nonce_data.value = self.generate_config.generate_nonce();
            nonce_data.expires_at = now + nonce_expiry_duration;
        }
        nonce_data
    }
}

struct RandomState {
    k0: u64,
    k1: u64,
}

fn new_hashmap_keys() -> (u64, u64) {
    #[cfg(not(feature = "std"))]
    {
        use rand::Rng;
        use rand::TryRngCore;
        let mut rng = rand::rngs::OsRng.unwrap_err();
        rng.random()
    }
    #[cfg(feature = "std")]
    {
        use rand::Rng;
        let mut rng = rand::rng();
        rng.random()
    }
}

impl RandomState {
    fn new() -> Self {
        #[cfg(not(feature = "std"))]
        {
            let (k0, k1) = new_hashmap_keys();
            RandomState { k0, k1 }
        }
        #[cfg(feature = "std")]
        {
            std::thread_local!(static KEYS: core::cell::Cell<(u64, u64)> = {
                core::cell::Cell::new(new_hashmap_keys())
            });

            KEYS.with(|keys| {
                let (k0, k1) = keys.get();
                keys.set((k0.wrapping_add(1), k1));
                RandomState { k0, k1 }
            })
        }
    }
}

impl core::hash::BuildHasher for RandomState {
    type Hasher = SipHasher;
    fn build_hasher(&self) -> Self::Hasher {
        SipHasher::new_with_keys(self.k0, self.k1)
    }
}

fn new_hash<K, V>() -> HashMap<K, V, RandomState> {
    HashMap::with_hasher(RandomState::new())
}

impl LongTermServerAuth {
    /// Construct an authentication method for long term credential handling on a server.
    pub fn new(realm: String) -> Self {
        // only used to prevent username retrieval through timing attacks. This is not a master key
        // bypass :).
        let backup_credentials =
            LongTermCredentials::new("default-user".to_string(), "default-password".to_string());
        let mut backup_integrity = new_hash();
        backup_integrity.insert(
            IntegrityAlgorithm::Sha1,
            backup_credentials
                .to_key(realm.clone())
                .make_key(IntegrityAlgorithm::Sha1),
        );
        backup_integrity.insert(
            IntegrityAlgorithm::Sha256,
            backup_credentials
                .to_key(realm.clone())
                .make_key(IntegrityAlgorithm::Sha256),
        );
        Self {
            realm: realm.clone(),
            nonces: LongTermNonce {
                generate_config: NonceConfiguration {
                    supported_integrity: smallvec::SmallVec::from_iter([IntegrityAlgorithm::Sha1]),
                    anonymous_username: Feature::default(),
                },
                nonce_expiry_duration: DEFAULT_NONCE_EXPIRY_DURATION,
                nonces: new_hash(),
            },
            user_hash: new_hash(),
            users: new_hash(),
            clients: BTreeMap::default(),
            backup_integrity,
        }
    }

    /// The realm used for this server.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Set the local credentials that all messages should be signed with
    pub fn add_user(&mut self, credentials: LongTermCredentials) {
        if self.anonymous_username().possible() {
            let hash = Userhash::compute(credentials.username(), &self.realm);
            self.user_hash
                .entry(hash)
                .or_insert_with(|| credentials.username().to_string());
        }
        self.users
            .entry(credentials.username().to_string())
            .and_modify(|client| {
                for algo in self.nonces.generate_config.supported_integrity.iter() {
                    client
                        .keys
                        .entry(*algo)
                        .and_modify(|key| {
                            *key = credentials.to_key(self.realm.clone()).make_key(*algo)
                        })
                        .or_insert_with_key(|algo| {
                            credentials.to_key(self.realm.clone()).make_key(*algo)
                        });
                }
                client.credentials = credentials.clone();
            })
            .or_insert({
                let mut keys = new_hash();
                for algo in self.nonces.generate_config.supported_integrity.iter() {
                    keys.insert(
                        *algo,
                        credentials.to_key(self.realm.clone()).make_key(*algo),
                    );
                }

                ClientAuth { keys, credentials }
            });
    }

    /// The supported integrity algorithms used.
    pub fn supported_integrity(&self) -> &[IntegrityAlgorithm] {
        &self.nonces.generate_config.supported_integrity
    }

    /// Add a supported integrity algorithms that will be used.
    pub fn add_supported_integrity(&mut self, integrity: IntegrityAlgorithm) {
        let supported_integrity = &mut self.nonces.generate_config.supported_integrity;
        let idx = supported_integrity
            .partition_point(|item| rank_integrity(*item) >= rank_integrity(integrity));
        if idx == supported_integrity.len() || supported_integrity[idx] != integrity {
            debug!(
                "inserting {integrity:?} at {idx} of {:?}",
                supported_integrity
            );
            supported_integrity.insert(idx, integrity);
            for user in self.users.values_mut() {
                user.keys.insert(
                    integrity,
                    user.credentials
                        .to_key(self.realm.clone())
                        .make_key(integrity),
                );
            }
        }
    }

    /// Set the supported integrity algorithm used.
    pub fn set_supported_integrity(&mut self, integrity: IntegrityAlgorithm) {
        if self.nonces.generate_config.supported_integrity.as_ref() != [integrity] {
            self.nonces.generate_config.supported_integrity =
                smallvec::SmallVec::from_iter([integrity]);
            for user in self.users.values_mut() {
                user.keys.clear();
                user.keys.insert(
                    integrity,
                    user.credentials
                        .to_key(self.realm.clone())
                        .make_key(integrity),
                );
            }
        }
    }

    /// Set whether anonymous username usage is required.
    ///
    /// A value of `true` requires the server to support RFC 8489 and the [`Userhash`] attribute.
    pub fn set_anonymous_username(&mut self, anonymous: Feature) {
        if self.nonces.generate_config.anonymous_username.possible() != anonymous.possible() {
            if anonymous.possible() {
                for user in self.users.keys() {
                    let hash = Userhash::compute(user, &self.realm);
                    self.user_hash.insert(hash, user.clone());
                }
            } else {
                self.user_hash.clear();
            }
        }
        self.nonces.generate_config.anonymous_username = anonymous;
    }

    /// Whether anonymous username usage is required.
    ///
    /// A value of true requires the server to support RFC 8489 and the [`Userhash`] attribute.
    pub fn anonymous_username(&mut self) -> Feature {
        self.nonces.generate_config.anonymous_username
    }

    /// Remove a user from being able to access this server.
    pub fn remove_user(&mut self, user: &str) {
        self.users.remove(user);
    }

    /// Set the amount of time that nonces are valid for.
    pub fn set_nonce_expiry_duration(&mut self, expiry_duration: Duration) {
        if expiry_duration < MINIMUM_NONCE_EXPIRY_DURATION {
            panic!("Attempted to set a nonce expiry duration ({expiry_duration:?}) of less than the allowed minimum ({MINIMUM_NONCE_EXPIRY_DURATION:?})");
        }
        self.nonces.nonce_expiry_duration = expiry_duration;
    }

    /// Return the currently configured nonce for a particular client.
    pub fn nonce_for_client(&self, client: SocketAddr) -> Option<&str> {
        self.nonces
            .nonces
            .get(&client)
            .map(|nonce| nonce.value.deref())
    }

    /// Number of bytes required to successfully add message integrity to an outgoing message.
    pub fn message_signature_bytes(&self, to: SocketAddr, user: &str, is_request: bool) -> usize {
        if let Some(nonce_len) = self
            .nonces
            .nonces
            .get(&to)
            .map(|nonce| 4 + pad_attribute_len(nonce.value.len()))
        {
            let user_algo_len = self
                .users
                .get(user)
                .map(|auth| {
                    auth.keys
                        .keys()
                        .map(|algo| bytes_for_integrity(*algo))
                        .sum::<usize>()
                })
                .unwrap_or_default();
            if is_request {
                nonce_len + user_algo_len + 4 + pad_attribute_len(self.realm.len())
            } else {
                user_algo_len
            }
        } else {
            0
        }
    }

    /// Sign an outgoing STUN message.
    #[tracing::instrument(name = "server_sign_outgoing_message", skip(self, msg), err(Debug))]
    pub fn sign_outgoing_message<W: MessageWrite>(
        &mut self,
        mut msg: W,
        user: &str,
        to: SocketAddr,
    ) -> Result<W, StunWriteError> {
        // this is an address we have received data from succesfully and generated a nonce.
        let Some(nonce) = self.nonces.nonces.get_mut(&to) else {
            return Ok(msg);
        };
        if msg.is_response() {
            msg.add_attribute(&Nonce::new(&nonce.value)?)?;
            msg.add_attribute(&Realm::new(&self.realm)?)?;
        }
        if let Some((user, algo)) = self.clients.get(&to) {
            // we have a successful client for this connection and should therefore have succesful
            // auth.
            let Some(auth) = self.users.get(user) else {
                return Err(StunWriteError::IntegrityFailed);
            };
            let Some(key) = auth.keys.get(algo) else {
                return Err(StunWriteError::IntegrityFailed);
            };
            if *algo != IntegrityAlgorithm::Sha1 {
                msg.add_attribute(&PasswordAlgorithm::new(match algo {
                    IntegrityAlgorithm::Sha1 => unreachable!(),
                    IntegrityAlgorithm::Sha256 => PasswordAlgorithmValue::SHA256,
                }))?;
            }
            msg.add_message_integrity_with_key(key, *algo)?;
        } else if msg.is_response() {
            let algos = self
                .nonces
                .generate_config
                .supported_integrity
                .iter()
                .map(|algo| match algo {
                    IntegrityAlgorithm::Sha1 => PasswordAlgorithmValue::MD5,
                    IntegrityAlgorithm::Sha256 => PasswordAlgorithmValue::SHA256,
                })
                .collect::<smallvec::SmallVec<_>>();
            msg.add_attribute(&PasswordAlgorithms::new(&algos))?;
            nonce.password_algorithms = algos;
        }
        Ok(msg)
    }

    /// Validate an incoming message according to the rules of the STUN long term credentials
    /// mechanism for servers.
    #[tracing::instrument(
        name = "server_validate_incoming_message",
        skip(self, msg, now),
        err(Debug)
    )]
    pub fn validate_incoming_message(
        &mut self,
        msg: &Message<'_>,
        from: SocketAddr,
        now: Instant,
    ) -> Result<LongTermValidation, AuthError> {
        if msg.is_response() {
            if let Some(key) = self.clients.get(&from).and_then(|user| {
                self.users
                    .get(&user.0)
                    .and_then(|auth| auth.keys.get(&user.1))
            }) {
                msg.validate_integrity_with_key(key)
                    .map(LongTermValidation::Validated)
                    .map_err(|e| AuthError {
                        reason: e.into(),
                        integrity: None,
                    })
            } else {
                Err(AuthError {
                    reason: AuthErrorReason::IntegrityFailed,
                    integrity: None,
                })
            }
        } else {
            let mut integrity = None;
            let mut integrity_sha256 = None;
            let mut username = None;
            let mut userhash = None;
            let mut realm = None;
            let mut nonce = None;
            let mut password_algo = None;
            let mut password_algos = None;

            for (_offset, attr) in msg.iter_attributes() {
                match attr.get_type() {
                    MessageIntegrity::TYPE => integrity = MessageIntegrity::from_raw(attr).ok(),
                    MessageIntegritySha256::TYPE => {
                        integrity_sha256 = MessageIntegritySha256::from_raw(attr).ok()
                    }
                    Username::TYPE => username = Username::from_raw(attr).ok(),
                    Userhash::TYPE => userhash = Userhash::from_raw(attr).ok(),
                    Realm::TYPE => realm = Realm::from_raw(attr).ok(),
                    Nonce::TYPE => nonce = Nonce::from_raw(attr).ok(),
                    PasswordAlgorithm::TYPE => {
                        password_algo = PasswordAlgorithm::from_raw(attr).ok()
                    }
                    PasswordAlgorithms::TYPE => {
                        password_algos = PasswordAlgorithms::from_raw(attr).ok()
                    }
                    _ => (),
                }
            }

            if integrity.is_none() && integrity_sha256.is_none() {
                //   o  If the message does not contain a MESSAGE-INTEGRITY attribute, the
                //      server MUST generate an error response with an error code of 401
                //      (Unauthorized).  This response MUST include a REALM value.  It is
                //      RECOMMENDED that the REALM value be the domain name of the
                //      provider of the STUN server.  The response MUST include a NONCE,
                //      selected by the server.  The response SHOULD NOT contain a
                //      USERNAME or MESSAGE-INTEGRITY attribute.
                let nonce_value = self.nonces.validate_nonce(from, now);
                trace!(
                    "no message-integrity, returning unauthorized with nonce: {}",
                    nonce_value.value
                );
                return Err(AuthError {
                    reason: AuthErrorReason::Unauthorized,
                    integrity: None,
                });
            }

            // o  If the message contains a MESSAGE-INTEGRITY or a MESSAGE-
            //    INTEGRITY-SHA256 attribute, but is missing either the USERNAME or
            //    USERHASH, REALM, or NONCE attribute, the server MUST generate an
            //    error response with an error code of 400 (Bad Request).  This
            //    response SHOULD NOT include a USERNAME, USERHASH, NONCE, or REALM
            //    attribute.  The response cannot contain a MESSAGE-INTEGRITY or
            //    MESSAGE-INTEGRITY-SHA256 attribute, as the attributes required to
            //    generate them are missing.
            let Some((_realm, nonce)) = realm.zip(nonce) else {
                trace!("bad request due to missing realm, or nonce");
                return Err(AuthError {
                    reason: AuthErrorReason::BadRequest,
                    integrity: None,
                });
            };
            let user = if let Some(hash) = userhash.as_ref() {
                self.user_hash.get(hash.hash()).map(|user| user.deref())
            } else if let Some(user) = username.as_ref() {
                Some(user.username())
            } else {
                trace!("bad request due to missing username, or userhash");
                return Err(AuthError {
                    reason: AuthErrorReason::BadRequest,
                    integrity: None,
                });
            };

            let nonce_value = self.nonces.validate_nonce(from, now);
            let password_algo = if let Some(security) = NonceSecurityBits::from_nonce(nonce.nonce())
            {
                // o  If the NONCE attribute starts with the "nonce cookie" with the
                //    STUN Security Feature "Password algorithms" bit set to 1, the
                //    server performs these checks in the order specified:
                if security.password_algorithms() {
                    // *  Otherwise, unless (1) PASSWORD-ALGORITHM and PASSWORD-
                    //    ALGORITHMS are both present, (2) PASSWORD-ALGORITHMS matches
                    //    the value sent in the response that sent this NONCE, and (3)
                    //    PASSWORD-ALGORITHM matches one of the entries in PASSWORD-
                    //    ALGORITHMS, the server MUST generate an error response with an
                    //    error code of 400 (Bad Request).
                    if let Some((algo, algos)) = password_algo.as_ref().zip(password_algos.as_ref())
                    {
                        if !algos.algorithms().contains(&algo.algorithm()) {
                            return Err(AuthError {
                                reason: AuthErrorReason::BadRequest,
                                integrity: None,
                            });
                        }
                        if algos.algorithms() != nonce_value.password_algorithms.as_ref() {
                            return Err(AuthError {
                                reason: AuthErrorReason::BadRequest,
                                integrity: None,
                            });
                        }
                        algo.algorithm().as_integrity()
                    } else {
                        trace!(
                            "bad request due to missing password algorithm, or password algorithms"
                        );
                        return Err(AuthError {
                            reason: AuthErrorReason::BadRequest,
                            integrity: None,
                        });
                    }
                } else {
                    IntegrityAlgorithm::Sha1
                }
            } else {
                IntegrityAlgorithm::Sha1
            };

            //   o  If the NONCE is no longer valid, the server MUST generate an error
            //      response with an error code of 438 (Stale Nonce).  This response
            //      MUST include NONCE and REALM attributes and SHOULD NOT include the
            //      USERNAME or MESSAGE-INTEGRITY attribute.  Servers can invalidate
            //      nonces in order to provide additional security.  See Section 4.3
            //      of [RFC2617] for guidelines.
            if nonce_value.value != nonce.nonce() {
                if let Some(security) = NonceSecurityBits::from_nonce(&nonce_value.value) {
                    if let Some(request_security) = NonceSecurityBits::from_nonce(nonce.nonce()) {
                        if security != request_security {
                            // something is in the middle modifying nonces. This is problematic.
                            return Err(AuthError {
                                reason: AuthErrorReason::Unauthorized,
                                integrity: None,
                            });
                        }
                    }
                }
                trace!("stale nonce {} vs {}", nonce_value.value, nonce.nonce());
                return Err(AuthError {
                    reason: AuthErrorReason::StaleNonce,
                    integrity: None,
                });
            }

            //   o  Using the password associated with the username in the USERNAME
            //      attribute, compute the value for the message integrity as
            //      described in Section 15.4.  If the resulting value does not match
            //      the contents of the MESSAGE-INTEGRITY attribute, the server MUST
            //      reject the request with an error response.  This response MUST use
            //      an error code of 401 (Unauthorized).  It MUST include REALM and
            //      NONCE attributes and SHOULD NOT include the USERNAME or MESSAGE-
            //      INTEGRITY attribute.
            let Some(client) = user.and_then(|user| self.users.get(user)) else {
                // unknown username will still run integrity checks (to avoid username retrieval
                // through timing attacks) but always return integrity failed.
                let Some(key) = self.backup_integrity.get(&password_algo) else {
                    warn!("No backup integrity! Timing attack on usernames possible!");
                    return Err(AuthError {
                        reason: AuthErrorReason::Unauthorized,
                        integrity: None,
                    });
                };
                let _ = msg.validate_integrity_with_key(key);
                trace!("integrity failed");
                return Err(AuthError {
                    reason: AuthErrorReason::Unauthorized,
                    integrity: None,
                });
            };
            let Some(key) = client.keys.get(&password_algo) else {
                trace!("no key for password algo {password_algo:?}");
                let Some(key) = self.backup_integrity.get(&password_algo) else {
                    warn!("No backup integrity! Timing attack on usernames possible!");
                    return Err(AuthError {
                        reason: AuthErrorReason::Unauthorized,
                        integrity: None,
                    });
                };
                let _ = msg.validate_integrity_with_key(key);
                trace!("integrity failed");
                return Err(AuthError {
                    reason: AuthErrorReason::Unauthorized,
                    integrity: None,
                });
            };
            if msg.validate_integrity_with_key(key).is_err() {
                trace!("integrity failed");
                return Err(AuthError {
                    reason: AuthErrorReason::Unauthorized,
                    integrity: None,
                });
            }
            self.clients.insert(
                from,
                (client.credentials.username().to_string(), password_algo),
            );
            Ok(LongTermValidation::Validated(password_algo))
        }
    }
}

fn is_valid_stale_nonce(msg: &Message<'_>) -> Option<(Nonce, Realm)> {
    if !msg.has_class(MessageClass::Error) {
        return None;
    }
    let Ok(error) = msg.attribute::<ErrorCode>() else {
        return None;
    };
    if error.code() != ErrorCode::STALE_NONCE {
        return None;
    }
    let Ok(nonce) = msg.attribute::<Nonce>() else {
        return None;
    };
    let Ok(realm) = msg.attribute::<Realm>() else {
        return None;
    };

    Some((nonce, realm))
}

fn rank_integrity(integrity: IntegrityAlgorithm) -> usize {
    match integrity {
        IntegrityAlgorithm::Sha1 => 1,
        IntegrityAlgorithm::Sha256 => 2,
    }
}

#[cfg(test)]
mod tests {
    use stun_types::{
        attribute::{MessageIntegritySha256, Userhash},
        message::{MessageType, MessageWriteVec, TransactionId, BINDING},
    };

    use super::*;

    use alloc::vec::Vec;

    #[test]
    fn nonce_security() {
        let _log = crate::tests::test_init_log();
        for i in 0..24 {
            let n: u32 = 1 << i;
            let security = NonceSecurityBits {
                bytes: n.to_be_bytes()[1..].try_into().unwrap(),
            };
            assert_eq!(security.password_algorithms(), i == 23);
            assert_eq!(security.username_anonymity(), i == 22);
            trace!("initial security bits {security:x?}");
            let nonce = security.as_string();
            trace!("security nonce: {nonce}");
            let security2 = NonceSecurityBits::from_nonce(&nonce).unwrap();
            trace!("parsed security bits {security2:x?}");
            assert_eq!(security, security2);
        }
    }

    #[test]
    fn short_term_getters() {
        let _log = crate::tests::test_init_log();

        let mut auth = ShortTermAuth::new();
        assert!(auth.integrity_key().is_none());
        assert_eq!(auth.message_signature_bytes(), 0);

        let credentials = ShortTermCredentials::new(String::from("password"));
        auth.set_credentials(credentials.clone(), IntegrityAlgorithm::Sha1);
        assert_eq!(
            auth.credentials(),
            Some((&credentials, IntegrityAlgorithm::Sha1))
        );
        assert!(auth.integrity_key().is_some());
        assert_eq!(auth.message_signature_bytes(), 24);

        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let msg = auth.sign_outgoing_message(msg).unwrap();
        let request = msg.finish();
        let request = Message::from_bytes(&request).unwrap();
        assert_eq!(
            request.validate_integrity(&credentials.into()).unwrap(),
            IntegrityAlgorithm::Sha1
        );
        assert_eq!(
            request
                .validate_integrity_with_key(auth.integrity_key().unwrap())
                .unwrap(),
            IntegrityAlgorithm::Sha1
        );
    }

    #[test]
    fn short_term_no_credentials() {
        let _log = crate::tests::test_init_log();

        let mut auth = ShortTermAuth::new();
        assert!(auth.integrity_key().is_none());
        assert_eq!(auth.message_signature_bytes(), 0);

        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let msg = auth.sign_outgoing_message(msg).unwrap();
        let request = msg.finish();
        let request = Message::from_bytes(&request).unwrap();
        assert!(msg_has_no_auth(&request));

        assert!(matches!(auth.validate_incoming_message(&request), Ok(None)));
    }

    #[test]
    fn long_term_client_getters() {
        let _log = crate::tests::test_init_log();

        let mut auth = LongTermClientAuth::new();
        assert!(auth.credentials().is_none());
        assert_eq!(auth.message_signature_bytes(), 0);
        assert_eq!(auth.supported_integrity(), &[IntegrityAlgorithm::Sha1]);
        auth.add_supported_integrity(IntegrityAlgorithm::Sha256);
        assert_eq!(
            auth.supported_integrity(),
            &[IntegrityAlgorithm::Sha1, IntegrityAlgorithm::Sha256]
        );
        auth.set_supported_integrity(IntegrityAlgorithm::Sha1);
        assert_eq!(auth.supported_integrity(), &[IntegrityAlgorithm::Sha1]);
        auth.set_anonymous_username(Feature::Required);
        assert_eq!(auth.anonymous_username(), Feature::Required);
        auth.set_anonymous_username(Feature::Disabled);
        assert_eq!(auth.anonymous_username(), Feature::Disabled);
        auth.set_anonymous_username(Feature::Auto);
        assert_eq!(auth.anonymous_username(), Feature::Auto);

        let credentials = LongTermCredentials::new("user".to_string(), "password".to_string());
        auth.set_credentials(credentials.clone());
        assert_eq!(auth.credentials(), Some(&credentials));
        // no realm from the server yet so cannot currently sign messages
        assert_eq!(auth.message_signature_bytes(), 0);

        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let msg = auth.sign_outgoing_message(msg).unwrap();
        let request = msg.finish();
        let request = Message::from_bytes(&request).unwrap();
        assert!(msg_has_no_auth(&request));

        // unsigned message is ignored
        let response = Message::builder_success(&request, MessageWriteVec::new());
        let response = response.finish();
        let response = Message::from_bytes(&response).unwrap();
        assert!(matches!(
            auth.validate_incoming_message(&response),
            Err(AuthError {
                reason: AuthErrorReason::IntegrityFailed,
                integrity: None,
            })
        ));
    }

    #[test]
    fn auth_error_getters() {
        for reason in [
            AuthErrorReason::BadRequest,
            AuthErrorReason::StaleNonce,
            AuthErrorReason::Unauthorized,
            AuthErrorReason::IntegrityFailed,
            StunParseError::NotStun.into(),
        ] {
            for integrity in [
                None,
                Some(IntegrityAlgorithm::Sha1),
                Some(IntegrityAlgorithm::Sha256),
            ] {
                let err = AuthError { reason, integrity };
                assert_eq!(err.reason(), reason);
                assert_eq!(err.integrity(), integrity);
            }
        }
    }

    #[test]
    fn long_term_server_getters() {
        let _log = crate::tests::test_init_log();
        let client_addr = "10.0.0.1:12345".parse().unwrap();
        let now = Instant::ZERO;

        let mut auth = LongTermServerAuth::new("realm".to_string());
        let credentials = LongTermCredentials::new("user".to_string(), "password".to_string());
        auth.add_user(credentials.clone());
        // no negotiation with a client yet so cannot currently sign messages
        assert_eq!(
            auth.message_signature_bytes(client_addr, credentials.username(), false),
            0
        );
        assert_eq!(
            auth.message_signature_bytes(client_addr, credentials.username(), true),
            0
        );
        auth.add_supported_integrity(IntegrityAlgorithm::Sha256);
        assert_eq!(
            auth.supported_integrity(),
            &[IntegrityAlgorithm::Sha256, IntegrityAlgorithm::Sha1]
        );
        auth.set_supported_integrity(IntegrityAlgorithm::Sha1);
        assert_eq!(auth.supported_integrity(), &[IntegrityAlgorithm::Sha1]);
        auth.set_anonymous_username(Feature::Required);
        assert_eq!(auth.anonymous_username(), Feature::Required);
        auth.set_anonymous_username(Feature::Disabled);
        assert_eq!(auth.anonymous_username(), Feature::Disabled);
        auth.set_anonymous_username(Feature::Auto);
        assert_eq!(auth.anonymous_username(), Feature::Auto);

        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let msg = auth
            .sign_outgoing_message(msg, credentials.username(), client_addr)
            .unwrap();
        let request = msg.finish();
        let request = Message::from_bytes(&request).unwrap();
        assert!(msg_has_no_auth(&request));

        // unsigned message is ignored
        let response = Message::builder_success(&request, MessageWriteVec::new());
        let response = response.finish();
        let response = Message::from_bytes(&response).unwrap();
        assert!(matches!(
            auth.validate_incoming_message(&response, client_addr, now),
            Err(AuthError {
                reason: AuthErrorReason::IntegrityFailed,
                integrity: None,
            })
        ));
    }

    fn msg_has_no_auth(msg: &Message<'_>) -> bool {
        msg.attribute::<Username>().is_err()
            && msg.attribute::<Userhash>().is_err()
            && msg.attribute::<Nonce>().is_err()
            && msg.attribute::<Realm>().is_err()
            && msg.attribute::<MessageIntegrity>().is_err()
            && msg.attribute::<MessageIntegritySha256>().is_err()
    }

    fn server_unauthorized_response(msg: &Message<'_>) -> MessageWriteVec {
        let mut response = Message::builder_error(msg, MessageWriteVec::new());
        response
            .add_attribute(&ErrorCode::builder(ErrorCode::UNAUTHORIZED).build().unwrap())
            .unwrap();
        response
    }

    #[derive(Debug)]
    struct LongTermTest {
        client: LongTermClientAuth,
        server: LongTermServerAuth,
        client_addr: SocketAddr,
    }

    impl LongTermTest {
        fn new() -> Self {
            let client_addr = "10.0.0.1:12345".parse().unwrap();
            let realm = "realm".to_string();
            let credentials = LongTermCredentials::new("user".to_string(), "pass".to_string());
            let mut client = LongTermClientAuth::new();
            client.set_credentials(credentials.clone());
            let mut server = LongTermServerAuth::new(realm);
            server.add_user(credentials);

            Self {
                client,
                server,
                client_addr,
            }
        }

        fn initial_auth(&mut self, now: Instant) -> Result<LongTermValidation, AuthError> {
            let msg = Message::builder_request(BINDING, MessageWriteVec::new());
            let msg = self.client.sign_outgoing_message(msg).unwrap().finish();
            let msg = Message::from_bytes(&msg).unwrap();
            assert!(matches!(
                self.server
                    .validate_incoming_message(&msg, self.client_addr, now),
                Err(AuthError {
                    reason: AuthErrorReason::Unauthorized,
                    integrity: None,
                })
            ));
            let response = server_unauthorized_response(&msg);
            let user = self.client.credentials().unwrap().username().to_string();
            let response = self
                .server
                .sign_outgoing_message(response, &user, self.client_addr)
                .unwrap()
                .finish();
            let response = Message::from_bytes(&response).unwrap();
            self.client.validate_incoming_message(&response)
        }

        fn full_auth(
            &mut self,
            now: Instant,
            integrity: IntegrityAlgorithm,
        ) -> Result<LongTermValidation, AuthError> {
            let msg = Message::builder_request(BINDING, MessageWriteVec::new());
            let msg = self.client.sign_outgoing_message(msg).unwrap().finish();
            let msg = Message::from_bytes(&msg).unwrap();
            assert!(!msg_has_no_auth(&msg));
            assert!(matches!(
                self.server
                    .validate_incoming_message(&msg, self.client_addr, now),
                Ok(LongTermValidation::Validated(algo)) if algo == integrity
            ));

            let response = Message::builder_success(&msg, MessageWriteVec::new());
            let response = self
                .server
                .sign_outgoing_message(
                    response,
                    self.client.credentials().unwrap().username(),
                    self.client_addr,
                )
                .unwrap();
            let response = response.finish();
            let response = Message::from_bytes(&response).unwrap();
            self.client.validate_incoming_message(&response)
        }

        fn server_generate_stale_nonce(&self, msg: &Message<'_>) -> MessageWriteVec {
            let mut response = Message::builder_error(msg, MessageWriteVec::new());
            response
                .add_attribute(&ErrorCode::builder(ErrorCode::STALE_NONCE).build().unwrap())
                .unwrap();
            response
                .add_attribute(&Realm::new(self.server.realm()).unwrap())
                .unwrap();
            response
                .add_attribute(
                    &Nonce::new(self.server.nonce_for_client(self.client_addr).unwrap()).unwrap(),
                )
                .unwrap();
            response
        }
    }

    #[test]
    fn long_term_initial_client_sign_noop() {
        let _log = crate::tests::test_init_log();

        let mut test = LongTermTest::new();
        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let msg = test.client.sign_outgoing_message(msg).unwrap().finish();
        let msg = Message::from_bytes(&msg).unwrap();
        assert!(msg_has_no_auth(&msg));
    }

    #[test]
    fn long_term_full_auth_username_sha1() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.client.set_anonymous_username(Feature::Disabled);
        test.server.set_anonymous_username(Feature::Disabled);
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        assert!(matches!(
            test.full_auth(now, IntegrityAlgorithm::Sha1),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));
        assert_eq!(
            test.server.message_signature_bytes(
                test.client_addr,
                test.client.credentials().unwrap().username(),
                true
            ),
            56
        );
        assert_eq!(
            test.server.message_signature_bytes(
                test.client_addr,
                test.client.credentials().unwrap().username(),
                false
            ),
            24
        );
    }

    #[test]
    fn long_term_full_auth_userhash_sha1() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.client.set_anonymous_username(Feature::Required);
        test.server.set_anonymous_username(Feature::Required);
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        assert!(matches!(
            test.full_auth(now, IntegrityAlgorithm::Sha1),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));
        assert_eq!(
            test.server.message_signature_bytes(
                test.client_addr,
                test.client.credentials().unwrap().username(),
                true
            ),
            72
        );
        assert_eq!(
            test.server.message_signature_bytes(
                test.client_addr,
                test.client.credentials().unwrap().username(),
                false
            ),
            24
        );
    }

    #[test]
    fn long_term_full_auth_userhash_sha256() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.client.set_anonymous_username(Feature::Required);
        test.client
            .set_supported_integrity(IntegrityAlgorithm::Sha256);
        test.server.set_anonymous_username(Feature::Required);
        test.server
            .set_supported_integrity(IntegrityAlgorithm::Sha256);
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        assert!(matches!(
            test.full_auth(now, IntegrityAlgorithm::Sha256),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha256))
        ));
        assert_eq!(
            test.server.message_signature_bytes(
                test.client_addr,
                test.client.credentials().unwrap().username(),
                true
            ),
            84
        );
        assert_eq!(
            test.server.message_signature_bytes(
                test.client_addr,
                test.client.credentials().unwrap().username(),
                false
            ),
            36
        );
    }

    #[test]
    fn long_term_full_auth_uses_sha256() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let auths = [
            [IntegrityAlgorithm::Sha256].as_ref(),
            [IntegrityAlgorithm::Sha1, IntegrityAlgorithm::Sha256].as_ref(),
            [IntegrityAlgorithm::Sha256, IntegrityAlgorithm::Sha1].as_ref(),
        ];

        for client in auths.iter() {
            for server in auths.iter() {
                std::println!(
                    "creating test with client auth {client:?} and server auth {server:?}"
                );
                let mut test = LongTermTest::new();
                test.client.set_supported_integrity(client[0]);
                for client in client[1..].iter() {
                    test.client.add_supported_integrity(*client);
                }
                test.server.set_supported_integrity(server[0]);
                for server in server[1..].iter() {
                    test.server.add_supported_integrity(*server);
                }
                assert!(matches!(
                    test.initial_auth(now),
                    Ok(LongTermValidation::ResendRequest(None))
                ));
                assert!(matches!(
                    test.full_auth(now, IntegrityAlgorithm::Sha256),
                    Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha256))
                ));
            }
        }
    }

    #[test]
    fn long_term_full_auth_flow_userhash_mismatch() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.client.set_anonymous_username(Feature::Required);
        test.server.set_anonymous_username(Feature::Disabled);
        assert!(matches!(
            test.initial_auth(now),
            Err(AuthError {
                reason,
                integrity,
            }) if reason == AuthErrorReason::UnsupportedFeature
        ));
    }

    #[test]
    fn long_term_full_auth_flow_server_sha256_mismatch() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.server
            .set_supported_integrity(IntegrityAlgorithm::Sha256);
        assert!(matches!(
            test.initial_auth(now),
            Err(AuthError {
                reason,
                integrity,
            }) if reason == AuthErrorReason::UnsupportedFeature
        ));
    }

    #[test]
    fn long_term_full_auth_flow_client_sha256_mismatch() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.server.set_anonymous_username(Feature::Disabled);
        test.client
            .set_supported_integrity(IntegrityAlgorithm::Sha256);
        assert!(matches!(
            test.initial_auth(now),
            Err(AuthError {
                reason,
                integrity,
            }) if reason == AuthErrorReason::UnsupportedFeature
        ));
    }

    #[test]
    fn long_term_full_auth_flow_client_sha1_mismatch() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.server.set_anonymous_username(Feature::Disabled);
        test.client
            .set_supported_integrity(IntegrityAlgorithm::Sha256);
        assert!(matches!(
            test.initial_auth(now),
            Err(AuthError {
                reason,
                integrity,
            }) if reason == AuthErrorReason::UnsupportedFeature
        ));
    }

    #[test]
    fn long_term_full_auth_stale_nonce() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.server
            .set_nonce_expiry_duration(MINIMUM_NONCE_EXPIRY_DURATION);
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        assert!(matches!(
            test.full_auth(now, IntegrityAlgorithm::Sha1),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));

        let now = now + MINIMUM_NONCE_EXPIRY_DURATION + Duration::from_secs(1);
        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let msg = test.client.sign_outgoing_message(msg).unwrap().finish();
        let msg = Message::from_bytes(&msg).unwrap();
        assert!(!msg_has_no_auth(&msg));
        assert!(matches!(
            test.server
                .validate_incoming_message(&msg, test.client_addr, now),
            Err(AuthError {
                reason: AuthErrorReason::StaleNonce,
                integrity: None,
            })
        ));
        let response = test.server_generate_stale_nonce(&msg).finish();
        let response = Message::from_bytes(&response).unwrap();
        assert!(matches!(
            test.client.validate_incoming_message(&response),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        assert!(matches!(
            test.full_auth(now, IntegrityAlgorithm::Sha1),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ))
    }

    #[test]
    fn long_term_initial_auth_bad_request() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.client.set_anonymous_username(Feature::Disabled);
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        for atype in [Realm::TYPE, Nonce::TYPE, Username::TYPE] {
            let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
            if atype != Username::TYPE {
                msg.add_attribute(
                    &Username::new(test.client.credentials().unwrap().username()).unwrap(),
                )
                .unwrap();
            }
            if atype != Realm::TYPE {
                msg.add_attribute(&Realm::new(test.server.realm()).unwrap())
                    .unwrap();
            }
            if atype != Nonce::TYPE {
                msg.add_attribute(
                    &Nonce::new(test.server.nonce_for_client(test.client_addr).unwrap()).unwrap(),
                )
                .unwrap();
            }
            msg.add_message_integrity(
                &test
                    .client
                    .credentials()
                    .unwrap()
                    .to_key(test.server.realm().to_string())
                    .into(),
                IntegrityAlgorithm::Sha1,
            )
            .unwrap();
            let msg = msg.finish();
            let msg = Message::from_bytes(&msg).unwrap();
            assert!(matches!(
                test.server
                    .validate_incoming_message(&msg, test.client_addr, now),
                Err(AuthError {
                    reason: AuthErrorReason::BadRequest,
                    integrity: None,
                })
            ));
        }
    }

    #[test]
    fn long_term_full_auth_client_stale_nonce_missing_attributes() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        for atype in [Realm::TYPE, Nonce::TYPE] {
            let mut test = LongTermTest::new();
            assert!(matches!(
                test.initial_auth(now),
                Ok(LongTermValidation::ResendRequest(None))
            ));
            assert!(matches!(
                test.full_auth(now, IntegrityAlgorithm::Sha1),
                Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
            ));

            let mut response = Message::builder(
                MessageType::from_class_method(MessageClass::Error, BINDING),
                TransactionId::generate(),
                MessageWriteVec::new(),
            );
            response
                .add_attribute(&ErrorCode::builder(ErrorCode::STALE_NONCE).build().unwrap())
                .unwrap();
            if atype != Realm::TYPE {
                response
                    .add_attribute(&Realm::new(test.server.realm()).unwrap())
                    .unwrap();
            }
            if atype != Nonce::TYPE {
                response
                    .add_attribute(
                        &Nonce::new(test.server.nonce_for_client(test.client_addr).unwrap())
                            .unwrap(),
                    )
                    .unwrap();
            }
            let response = Message::from_bytes(&response).unwrap();
            assert!(matches!(
                test.client.validate_incoming_message(&response),
                Err(AuthError {
                    reason: AuthErrorReason::IntegrityFailed,
                    integrity: None,
                })
            ));
        }
    }

    #[test]
    fn long_term_full_auth_client_bad_request_authed() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        assert!(matches!(
            test.full_auth(now, IntegrityAlgorithm::Sha1),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));

        let mut response = Message::builder(
            MessageType::from_class_method(MessageClass::Error, BINDING),
            TransactionId::generate(),
            MessageWriteVec::new(),
        );
        response
            .add_attribute(&ErrorCode::builder(ErrorCode::BAD_REQUEST).build().unwrap())
            .unwrap();
        let response = test
            .server
            .sign_outgoing_message(
                response,
                test.client.credentials.as_ref().unwrap().username(),
                test.client_addr,
            )
            .unwrap()
            .finish();
        let response = Message::from_bytes(&response).unwrap();
        assert!(matches!(
            test.client.validate_incoming_message(&response),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));
    }

    #[test]
    fn long_term_full_auth_client_bad_request_unauthed() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        assert!(matches!(
            test.full_auth(now, IntegrityAlgorithm::Sha1),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));

        let mut response = Message::builder(
            MessageType::from_class_method(MessageClass::Error, BINDING),
            TransactionId::generate(),
            MessageWriteVec::new(),
        );
        response
            .add_attribute(&ErrorCode::builder(ErrorCode::BAD_REQUEST).build().unwrap())
            .unwrap();
        let response = response.finish();
        let response = Message::from_bytes(&response).unwrap();
        assert!(matches!(
            test.client.validate_incoming_message(&response),
            Err(AuthError {
                reason: AuthErrorReason::IntegrityFailed,
                integrity: None,
            })
        ));
    }

    #[test]
    fn long_term_full_auth_client_other_error_response_unauthed() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        assert!(matches!(
            test.full_auth(now, IntegrityAlgorithm::Sha1),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));

        let mut response = Message::builder(
            MessageType::from_class_method(MessageClass::Error, BINDING),
            TransactionId::generate(),
            MessageWriteVec::new(),
        );
        response
            .add_attribute(
                &ErrorCode::builder(ErrorCode::WRONG_CREDENTIALS)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let response = response.finish();
        let response = Message::from_bytes(&response).unwrap();
        assert!(matches!(
            test.client.validate_incoming_message(&response),
            Err(AuthError {
                reason: AuthErrorReason::IntegrityFailed,
                integrity: None,
            })
        ));
    }

    #[test]
    fn long_term_full_auth_client_other_error_response_authed() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        assert!(matches!(
            test.full_auth(now, IntegrityAlgorithm::Sha1),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));

        let mut response = Message::builder(
            MessageType::from_class_method(MessageClass::Error, BINDING),
            TransactionId::generate(),
            MessageWriteVec::new(),
        );
        response
            .add_attribute(
                &ErrorCode::builder(ErrorCode::WRONG_CREDENTIALS)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let response = test
            .server
            .sign_outgoing_message(
                response,
                test.client.credentials.as_ref().unwrap().username(),
                test.client_addr,
            )
            .unwrap()
            .finish();
        let response = Message::from_bytes(&response).unwrap();
        assert!(matches!(
            test.client.validate_incoming_message(&response),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));
    }

    #[test]
    fn long_term_full_auth_client_success_response_unauthed() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        assert!(matches!(
            test.full_auth(now, IntegrityAlgorithm::Sha1),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));

        let response = Message::builder(
            MessageType::from_class_method(MessageClass::Success, BINDING),
            TransactionId::generate(),
            MessageWriteVec::new(),
        );
        let response = response.finish();
        let response = Message::from_bytes(&response).unwrap();
        assert!(matches!(
            test.client.validate_incoming_message(&response),
            Err(AuthError {
                reason: AuthErrorReason::IntegrityFailed,
                integrity: None,
            })
        ));
    }

    #[test]
    fn long_term_full_auth_client_success_response_authed() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        assert!(matches!(
            test.full_auth(now, IntegrityAlgorithm::Sha1),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));

        let response = Message::builder(
            MessageType::from_class_method(MessageClass::Success, BINDING),
            TransactionId::generate(),
            MessageWriteVec::new(),
        );
        let response = test
            .server
            .sign_outgoing_message(
                response,
                test.client.credentials.as_ref().unwrap().username(),
                test.client_addr,
            )
            .unwrap()
            .finish();
        let response = Message::from_bytes(&response).unwrap();
        assert!(matches!(
            test.client.validate_incoming_message(&response),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));
    }

    #[test]
    fn long_term_initial_auth_wrong_password() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        let user = test.client.credentials().unwrap().username().to_string();
        test.client.set_credentials(LongTermCredentials::new(
            user.clone(),
            "wrong-password".to_string(),
        ));
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let msg = test.client.sign_outgoing_message(msg).unwrap().finish();
        let msg = Message::from_bytes(&msg).unwrap();
        assert!(!msg_has_no_auth(&msg));
        assert!(matches!(
            test.server
                .validate_incoming_message(&msg, test.client_addr, now),
            Err(AuthError {
                reason: AuthErrorReason::Unauthorized,
                integrity: None
            })
        ));

        let response = server_unauthorized_response(&msg);
        let response = test
            .server
            .sign_outgoing_message(response, &user, test.client_addr)
            .unwrap()
            .finish();
        let response = Message::from_bytes(&response).unwrap();
        assert!(matches!(
            test.client.validate_incoming_message(&response),
            Err(AuthError {
                reason: AuthErrorReason::Unauthorized,
                integrity: None
            })
        ));
    }

    #[test]
    fn long_term_server_change_password() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.client.set_credentials(LongTermCredentials::new(
            test.client.credentials().unwrap().username().to_string(),
            "wrong-password".to_string(),
        ));
        test.server.add_user(LongTermCredentials::new(
            test.client.credentials().unwrap().username().to_string(),
            "wrong-password".to_string(),
        ));
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        assert!(matches!(
            test.full_auth(now, IntegrityAlgorithm::Sha1),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));
    }

    #[test]
    fn long_term_initial_auth_wrong_user() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        let expected_user = test.client.credentials().unwrap().username().to_string();
        test.client.set_credentials(LongTermCredentials::new(
            "wrong-user".to_string(),
            test.client.credentials().unwrap().password().to_string(),
        ));
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let msg = test.client.sign_outgoing_message(msg).unwrap().finish();
        let msg = Message::from_bytes(&msg).unwrap();
        assert!(!msg_has_no_auth(&msg));
        assert!(matches!(
            test.server
                .validate_incoming_message(&msg, test.client_addr, now),
            Err(AuthError {
                reason: AuthErrorReason::Unauthorized,
                integrity: None
            })
        ));

        let response = server_unauthorized_response(&msg);
        let response = test
            .server
            .sign_outgoing_message(response, &expected_user, test.client_addr)
            .unwrap()
            .finish();
        let response = Message::from_bytes(&response).unwrap();
        assert!(matches!(
            test.client.validate_incoming_message(&response),
            Err(AuthError {
                reason: AuthErrorReason::Unauthorized,
                integrity: None
            })
        ));
    }

    #[test]
    fn long_term_server_add_user() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.client.set_credentials(LongTermCredentials::new(
            "wrong-user".to_string(),
            test.client.credentials().unwrap().password().to_string(),
        ));
        test.server.add_user(LongTermCredentials::new(
            "wrong-user".to_string(),
            test.client.credentials().unwrap().password().to_string(),
        ));
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        assert!(matches!(
            test.full_auth(now, IntegrityAlgorithm::Sha1),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));
    }

    #[test]
    fn long_term_server_remove_user() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        test.server
            .remove_user(test.client.credentials.as_ref().unwrap().username());
        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let msg = test.client.sign_outgoing_message(msg).unwrap().finish();
        let msg = Message::from_bytes(&msg).unwrap();
        assert!(!msg_has_no_auth(&msg));
        assert!(matches!(
            test.server
                .validate_incoming_message(&msg, test.client_addr, now),
            Err(AuthError {
                reason: AuthErrorReason::Unauthorized,
                integrity: None
            })
        ));
    }

    #[test]
    fn long_term_client_request() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        assert!(matches!(
            test.initial_auth(now),
            Ok(LongTermValidation::ResendRequest(None))
        ));
        assert!(matches!(
            test.full_auth(now, IntegrityAlgorithm::Sha1),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ));

        let user = test
            .client
            .credentials
            .as_ref()
            .unwrap()
            .username()
            .to_string();

        let request = Message::builder_request(BINDING, MessageWriteVec::new());
        let request = test
            .server
            .sign_outgoing_message(request, &user, test.client_addr)
            .unwrap();
        let request = request.finish();
        let request = Message::from_bytes(&request).unwrap();
        trace!("sending request to client {request}");
        assert!(matches!(
            test.client.validate_incoming_message(&request).unwrap(),
            LongTermValidation::Validated(IntegrityAlgorithm::Sha1)
        ));

        let response = Message::builder_success(&request, MessageWriteVec::new());
        let response = test.client.sign_outgoing_message(response).unwrap();
        let response = response.finish();
        let response = Message::from_bytes(&response).unwrap();
        trace!("sending response to server {response}");
        assert!(matches!(
            test.server
                .validate_incoming_message(&response, test.client_addr, now)
                .unwrap(),
            LongTermValidation::Validated(IntegrityAlgorithm::Sha1)
        ));
    }

    fn test_server_bid_down_attack<F: FnOnce(&Message<'_>) -> Vec<u8>>(
        modify_response: F,
    ) -> Result<LongTermValidation, AuthError> {
        let now = Instant::ZERO;
        let mut test = LongTermTest::new();
        test.client
            .add_supported_integrity(IntegrityAlgorithm::Sha256);
        test.server
            .add_supported_integrity(IntegrityAlgorithm::Sha256);
        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let msg = test.client.sign_outgoing_message(msg).unwrap().finish();
        let msg = Message::from_bytes(&msg).unwrap();
        assert!(matches!(
            test.server
                .validate_incoming_message(&msg, test.client_addr, now),
            Err(AuthError {
                reason: AuthErrorReason::Unauthorized,
                integrity: None,
            })
        ));
        let response = server_unauthorized_response(&msg);
        let user = test.client.credentials().unwrap().username().to_string();
        let response = test
            .server
            .sign_outgoing_message(response, &user, test.client_addr)
            .unwrap()
            .finish();
        let response = Message::from_bytes(&response).unwrap();
        let response = modify_response(&response);
        let response = Message::from_bytes(&response).unwrap();
        assert!(matches!(
            test.client.validate_incoming_message(&response),
            Ok(LongTermValidation::ResendRequest(None)),
        ));
        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let msg = test.client.sign_outgoing_message(msg).unwrap().finish();
        let msg = Message::from_bytes(&msg).unwrap();
        assert!(!msg_has_no_auth(&msg));
        test.server
            .validate_incoming_message(&msg, test.client_addr, now)
    }

    #[test]
    fn long_term_full_server_bid_down_attack_remove_password_algorithms_from_server_response() {
        let _log = crate::tests::test_init_log();

        let ret = test_server_bid_down_attack(|response| {
            let mut new_response = Message::builder(
                response.get_type(),
                response.transaction_id(),
                MessageWriteVec::new(),
            );
            for (_offset, attr) in response.iter_attributes() {
                if attr.get_type() == Nonce::TYPE {
                    // strip the password algorithms indication from the nonce
                    let nonce = Nonce::from_raw_ref(&attr).unwrap();
                    let mut security = NonceSecurityBits::from_nonce(nonce.nonce()).unwrap();
                    assert!(security.password_algorithms());
                    security.set_password_algorithms(false);
                    let mut new_nonce = security.as_string();
                    new_nonce.push_str(&nonce.nonce()[LONG_TERM_RFC8489_NONCE_COOKIE.len() + 4..]);
                    new_response
                        .add_attribute(&Nonce::new(&new_nonce).unwrap())
                        .unwrap();
                } else if ![
                    PasswordAlgorithms::TYPE,
                    MessageIntegrity::TYPE,
                    MessageIntegritySha256::TYPE,
                ]
                .contains(&attr.get_type())
                {
                    new_response.add_attribute(&attr).unwrap();
                }
            }
            new_response.finish()
        });
        assert!(matches!(
            ret,
            Err(AuthError {
                reason,
                integrity,
            }) if reason == AuthErrorReason::Unauthorized
        ));
    }

    #[test]
    fn long_term_full_server_bid_down_attack_remove_password_algorithms_value_from_server_response()
    {
        let _log = crate::tests::test_init_log();

        let ret = test_server_bid_down_attack(|response| {
            let mut new_response = Message::builder(
                response.get_type(),
                response.transaction_id(),
                MessageWriteVec::new(),
            );
            for (_offset, attr) in response.iter_attributes() {
                if attr.get_type() == PasswordAlgorithms::TYPE {
                    new_response
                        .add_attribute(&PasswordAlgorithms::new(&[PasswordAlgorithmValue::MD5]))
                        .unwrap();
                } else if ![MessageIntegrity::TYPE, MessageIntegritySha256::TYPE]
                    .contains(&attr.get_type())
                {
                    new_response.add_attribute(&attr).unwrap();
                }
            }
            new_response.finish()
        });
        assert!(matches!(
            ret,
            Err(AuthError {
                reason,
                integrity,
            }) if reason == AuthErrorReason::BadRequest
        ));
    }

    fn test_client_bid_down_attack<F: FnOnce(&Message<'_>) -> Vec<u8>>(
        modify_response: F,
    ) -> Result<LongTermValidation, AuthError> {
        let now = Instant::ZERO;
        let mut test = LongTermTest::new();
        test.client
            .add_supported_integrity(IntegrityAlgorithm::Sha256);
        test.server
            .add_supported_integrity(IntegrityAlgorithm::Sha256);
        let msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let msg = test.client.sign_outgoing_message(msg).unwrap().finish();
        let msg = Message::from_bytes(&msg).unwrap();
        assert!(matches!(
            test.server
                .validate_incoming_message(&msg, test.client_addr, now),
            Err(AuthError {
                reason: AuthErrorReason::Unauthorized,
                integrity: None,
            })
        ));
        let response = server_unauthorized_response(&msg);
        let user = test.client.credentials().unwrap().username().to_string();
        let response = test
            .server
            .sign_outgoing_message(response, &user, test.client_addr)
            .unwrap()
            .finish();
        let response = Message::from_bytes(&response).unwrap();
        let response = modify_response(&response);
        let response = Message::from_bytes(&response).unwrap();
        test.client.validate_incoming_message(&response)
    }

    #[test]
    fn long_term_full_client_bid_down_attack_remove_password_algorithms_from_server_response() {
        let _log = crate::tests::test_init_log();

        let ret = test_client_bid_down_attack(|response| {
            let mut new_response = Message::builder(
                response.get_type(),
                response.transaction_id(),
                MessageWriteVec::new(),
            );
            for (_offset, attr) in response.iter_attributes() {
                if ![
                    PasswordAlgorithms::TYPE,
                    MessageIntegrity::TYPE,
                    MessageIntegritySha256::TYPE,
                ]
                .contains(&attr.get_type())
                {
                    new_response.add_attribute(&attr).unwrap();
                }
            }
            new_response.finish()
        });
        assert!(matches!(
            ret,
            Err(AuthError {
                reason,
                integrity,
            }) if reason == AuthErrorReason::Unauthorized
        ));
    }
}
