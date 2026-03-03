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
    pad_attribute_len, ErrorCode, MessageIntegrity, Nonce, Realm, Username,
};
use stun_types::message::{
    IntegrityAlgorithm, IntegrityKey, LongTermCredentials, Message, MessageClass,
    ShortTermCredentials, StunParseError, StunWriteError, ValidateError,
};
use stun_types::prelude::{
    Attribute, AttributeExt, AttributeFromRaw, AttributeStaticType, MessageWrite, MessageWriteExt,
};

use sans_io_time::Instant;
use tracing::trace;

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

#[derive(Debug)]
struct RequestAuth {
    username: String,
    realm: String,
    nonce: String,
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

/// Authentication for long term credentials.
#[derive(Debug, Default)]
pub struct LongTermClientAuth {
    credentials: Option<LongTermCredentials>,
    auth: AuthState,
    signature_bytes: usize,
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
        if let Some(auth) = self.auth.auth() {
            msg.add_attribute(&Nonce::new(&auth.nonce)?)?;
            msg.add_attribute(&Realm::new(&auth.realm)?)?;
            msg.add_attribute(&Username::new(&auth.username)?)?;
            msg.add_message_integrity_with_key(&auth.key, auth.algo)?;
            Ok(msg)
        } else {
            Ok(msg)
        }
    }

    /// Validate an incoming message according to the rules of the STUN long term credentials
    /// mechanism for clients.
    #[tracing::instrument(skip(self, msg), err(Debug))]
    pub fn validate_incoming_message(
        &mut self,
        msg: &Message<'_>,
    ) -> Result<LongTermValidation, AuthError> {
        let ret = if let Some(auth) = self.auth.auth() {
            msg.validate_integrity_with_key(&auth.key)
        } else {
            Err(ValidateError::IntegrityFailed)
        };
        if msg.is_response() {
            if msg.has_class(MessageClass::Error) {
                let mut realm = None;
                let mut nonce = None;
                let mut error_code = Err(StunParseError::MissingAttribute(ErrorCode::TYPE));
                for (_offset, attr) in msg.iter_attributes() {
                    match attr.get_type() {
                        Realm::TYPE => realm = Realm::from_raw(attr).ok(),
                        Nonce::TYPE => nonce = Nonce::from_raw(attr).ok(),
                        ErrorCode::TYPE => error_code = ErrorCode::from_raw(attr),
                        _ => (),
                    }
                }
                if let Ok(error_code) = error_code {
                    let reason = match error_code.code() {
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
                                let username = credentials.username().to_string();
                                let algo = IntegrityAlgorithm::Sha1;
                                self.signature_bytes = nonce.padded_len()
                                    + realm.padded_len()
                                    + bytes_for_integrity(algo);
                                let realm = realm.realm().to_string();
                                let key = credentials.to_key(realm.clone()).make_key(algo);
                                self.auth = AuthState::Authenticating(RequestAuth {
                                    username,
                                    realm,
                                    nonce: nonce.nonce().to_string(),
                                    key,
                                    algo,
                                });

                                trace!("retry request as credentials have changed");
                                return Ok(LongTermValidation::ResendRequest(ret.ok()));
                            } else {
                                // possible DoS?
                                AuthErrorReason::Unauthorized
                            }
                        }
                        ErrorCode::BAD_REQUEST => AuthErrorReason::BadRequest,
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
                            AuthErrorReason::IntegrityFailed
                        }
                        _ => {
                            return ret
                                .map(LongTermValidation::Validated)
                                .map_err(|e| AuthError {
                                    reason: e.into(),
                                    integrity: None,
                                })
                        }
                    };
                    return Err(AuthError {
                        reason,
                        integrity: ret.ok(),
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
}

#[derive(Debug)]
struct ClientAuth {
    credentials: LongTermCredentials,
    key_and_algo: (IntegrityAlgorithm, IntegrityKey),
}

static MINIMUM_NONCE_EXPIRY_DURATION: Duration = Duration::from_secs(30);
static DEFAULT_NONCE_EXPIRY_DURATION: Duration = Duration::from_secs(3600);

/// Authentication for long term credentials.
#[derive(Debug)]
pub struct LongTermServerAuth {
    nonce_expiry_duration: Duration,
    realm: String,
    nonces: HashMap<SocketAddr, ClientNonce, RandomState>,
    users: HashMap<String, ClientAuth, RandomState>,
    // remote address -> username
    clients: BTreeMap<SocketAddr, String>,
    backup_integrity: IntegrityKey,
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
        Self {
            nonce_expiry_duration: DEFAULT_NONCE_EXPIRY_DURATION,
            realm: realm.clone(),
            nonces: new_hash(),
            users: new_hash(),
            clients: BTreeMap::default(),
            backup_integrity: backup_credentials
                .to_key(realm)
                .make_key(IntegrityAlgorithm::Sha1),
        }
    }
    /// The realm used for this server.
    pub fn realm(&self) -> &str {
        &self.realm
    }
    /// Set the local credentials that all messages should be signed with
    pub fn add_user(&mut self, credentials: LongTermCredentials) {
        self.users
            .entry(credentials.username().to_string())
            .and_modify(|client| {
                client.key_and_algo = (
                    IntegrityAlgorithm::Sha1,
                    credentials
                        .to_key(self.realm.clone())
                        .make_key(IntegrityAlgorithm::Sha1),
                );
                client.credentials = credentials.clone();
            })
            .or_insert(ClientAuth {
                key_and_algo: (
                    IntegrityAlgorithm::Sha1,
                    credentials
                        .to_key(self.realm.clone())
                        .make_key(IntegrityAlgorithm::Sha1),
                ),
                credentials,
            });
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
        self.nonce_expiry_duration = expiry_duration;
    }

    /// Return the currently configured nonce for a particular client.
    pub fn nonce_for_client(&self, client: SocketAddr) -> Option<&str> {
        self.nonces.get(&client).map(|nonce| nonce.value.deref())
    }

    fn generate_nonce() -> String {
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

    fn validate_nonce(&mut self, from: SocketAddr, now: Instant) -> &str {
        let nonce_expiry_duration = self.nonce_expiry_duration;
        let nonce_data = self.nonces.entry(from).or_insert_with(|| ClientNonce {
            expires_at: now + self.nonce_expiry_duration,
            value: Self::generate_nonce(),
        });
        if nonce_data.expires_at < now {
            nonce_data.value = Self::generate_nonce();
            nonce_data.expires_at = now + nonce_expiry_duration;
        }
        &nonce_data.value
    }

    /// Number of bytes required to successfully add message integrity to an outgoing message.
    pub fn message_signature_bytes(&self, to: SocketAddr, user: &str, is_request: bool) -> usize {
        if let Some(nonce_len) = self
            .nonces
            .get(&to)
            .map(|nonce| 4 + pad_attribute_len(nonce.value.len()))
        {
            let user_algo_len = self
                .users
                .get(user)
                .map(|creds| bytes_for_integrity(creds.key_and_algo.0))
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
    #[tracing::instrument(skip(self, msg), err(Debug))]
    pub fn sign_outgoing_message<W: MessageWrite>(
        &mut self,
        mut msg: W,
        user: &str,
        to: SocketAddr,
    ) -> Result<W, StunWriteError> {
        if let Some((nonce, auth)) = self.nonces.get(&to).zip(self.users.get(user)) {
            if msg.has_class(MessageClass::Request) {
                msg.add_attribute(&Nonce::new(&nonce.value)?)?;
                msg.add_attribute(&Realm::new(&self.realm)?)?;
            }
            msg.add_message_integrity_with_key(&auth.key_and_algo.1, auth.key_and_algo.0)?;
            Ok(msg)
        } else {
            Ok(msg)
        }
    }

    /// Validate an incoming message according to the rules of the STUN long term credentials
    /// mechanism for servers.
    #[tracing::instrument(skip(self, msg, now), err(Debug))]
    pub fn validate_incoming_message(
        &mut self,
        msg: &Message<'_>,
        from: SocketAddr,
        now: Instant,
    ) -> Result<LongTermValidation, AuthError> {
        if msg.is_response() {
            if let Some(auth) = self
                .clients
                .get(&from)
                .and_then(|user| self.users.get(user))
            {
                msg.validate_integrity_with_key(&auth.key_and_algo.1)
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
            let mut username = None;
            let mut realm = None;
            let mut nonce = None;

            for (_offset, attr) in msg.iter_attributes() {
                match attr.get_type() {
                    MessageIntegrity::TYPE => integrity = MessageIntegrity::from_raw(attr).ok(),
                    Username::TYPE => username = Username::from_raw(attr).ok(),
                    Realm::TYPE => realm = Realm::from_raw(attr).ok(),
                    Nonce::TYPE => nonce = Nonce::from_raw(attr).ok(),
                    _ => (),
                }
            }

            // TODO: check for SHA256 integrity
            if integrity.is_none() {
                //   o  If the message does not contain a MESSAGE-INTEGRITY attribute, the
                //      server MUST generate an error response with an error code of 401
                //      (Unauthorized).  This response MUST include a REALM value.  It is
                //      RECOMMENDED that the REALM value be the domain name of the
                //      provider of the STUN server.  The response MUST include a NONCE,
                //      selected by the server.  The response SHOULD NOT contain a
                //      USERNAME or MESSAGE-INTEGRITY attribute.
                let nonce_value = self.validate_nonce(from, now);
                trace!("no message-integrity, returning unauthorized with nonce: {nonce_value}",);
                return Err(AuthError {
                    reason: AuthErrorReason::Unauthorized,
                    integrity: None,
                });
            }

            //  o  If the message contains a MESSAGE-INTEGRITY attribute, but is
            //      missing the USERNAME, REALM, or NONCE attribute, the server MUST
            //      generate an error response with an error code of 400 (Bad
            //      Request).  This response SHOULD NOT include a USERNAME, NONCE,
            //      REALM, or MESSAGE-INTEGRITY attribute.
            let Some(((username, _realm), nonce)) = username.zip(realm).zip(nonce) else {
                trace!("bad request due to missing username, realm, nonce");
                return Err(AuthError {
                    reason: AuthErrorReason::BadRequest,
                    integrity: None,
                });
            };

            //   o  If the NONCE is no longer valid, the server MUST generate an error
            //      response with an error code of 438 (Stale Nonce).  This response
            //      MUST include NONCE and REALM attributes and SHOULD NOT include the
            //      USERNAME or MESSAGE-INTEGRITY attribute.  Servers can invalidate
            //      nonces in order to provide additional security.  See Section 4.3
            //      of [RFC2617] for guidelines.
            let nonce_value = self.validate_nonce(from, now);
            if nonce_value != nonce.nonce() {
                trace!("stale nonce {nonce_value} vs {}", nonce.nonce());
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
            let Some(client) = self.users.get(username.username()) else {
                // unknown username will still run integrity checks (to avoid username retrieval
                // through timing attacks) but always return integrity failed.
                let _ = msg.validate_integrity_with_key(&self.backup_integrity);
                trace!("integrity failed");
                return Err(AuthError {
                    reason: AuthErrorReason::Unauthorized,
                    integrity: None,
                });
            };
            if msg
                .validate_integrity_with_key(&client.key_and_algo.1)
                .is_err()
            {
                trace!("integrity failed");
                return Err(AuthError {
                    reason: AuthErrorReason::Unauthorized,
                    integrity: None,
                });
            }
            Ok(LongTermValidation::Validated(client.key_and_algo.0))
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

#[cfg(test)]
mod tests {
    use stun_types::{
        attribute::{MessageIntegritySha256, Userhash},
        message::{MessageWriteVec, BINDING},
    };

    use super::*;

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

    fn server_unauthorized_response(
        server: &LongTermServerAuth,
        msg: &Message<'_>,
        client_addr: SocketAddr,
    ) -> MessageWriteVec {
        let mut response = Message::builder_error(msg, MessageWriteVec::new());
        response
            .add_attribute(&ErrorCode::builder(ErrorCode::UNAUTHORIZED).build().unwrap())
            .unwrap();
        response
            .add_attribute(&Realm::new(server.realm()).unwrap())
            .unwrap();
        response
            .add_attribute(&Nonce::new(server.nonce_for_client(client_addr).unwrap()).unwrap())
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

        fn initial_auth(&mut self, now: Instant) {
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
            let response =
                server_unauthorized_response(&self.server, &msg, self.client_addr).finish();
            let response = Message::from_bytes(&response).unwrap();
            assert!(matches!(
                self.client.validate_incoming_message(&response),
                Ok(LongTermValidation::ResendRequest(None))
            ));
        }

        fn full_auth(&mut self, now: Instant) -> Result<LongTermValidation, AuthError> {
            let msg = Message::builder_request(BINDING, MessageWriteVec::new());
            let msg = self.client.sign_outgoing_message(msg).unwrap().finish();
            let msg = Message::from_bytes(&msg).unwrap();
            assert!(!msg_has_no_auth(&msg));
            assert!(matches!(
                self.server
                    .validate_incoming_message(&msg, self.client_addr, now),
                Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
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
    fn long_term_full_auth_flow() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.initial_auth(now);
        assert!(matches!(
            test.full_auth(now),
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
    fn long_term_full_auth_stale_nonce() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.server
            .set_nonce_expiry_duration(MINIMUM_NONCE_EXPIRY_DURATION);
        test.initial_auth(now);
        assert!(matches!(
            test.full_auth(now),
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
            test.full_auth(now),
            Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
        ))
    }

    #[test]
    fn long_term_initial_auth_bad_request() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.initial_auth(now);
        for atype in [Realm::TYPE, Nonce::TYPE, Username::TYPE] {
            let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
            if atype == Username::TYPE {
                msg.add_attribute(
                    &Username::new(test.client.credentials().unwrap().username()).unwrap(),
                )
                .unwrap();
            }
            if atype == Realm::TYPE {
                msg.add_attribute(&Realm::new(test.server.realm()).unwrap())
                    .unwrap();
            }
            if atype == Nonce::TYPE {
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
    fn long_term_initial_auth_wrong_password() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.client.set_credentials(LongTermCredentials::new(
            test.client.credentials().unwrap().username().to_string(),
            "wrong-password".to_string(),
        ));
        test.initial_auth(now);
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

        let response = server_unauthorized_response(&test.server, &msg, test.client_addr).finish();
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
    fn long_term_initial_auth_wrong_user() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let mut test = LongTermTest::new();
        test.client.set_credentials(LongTermCredentials::new(
            "wrong-user".to_string(),
            test.client.credentials().unwrap().password().to_string(),
        ));
        test.initial_auth(now);
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

        let response = server_unauthorized_response(&test.server, &msg, test.client_addr).finish();
        let response = Message::from_bytes(&response).unwrap();
        assert!(matches!(
            test.client.validate_incoming_message(&response),
            Err(AuthError {
                reason: AuthErrorReason::Unauthorized,
                integrity: None
            })
        ));
    }
}
