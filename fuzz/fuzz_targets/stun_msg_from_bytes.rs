// SPDX-FileCopyrightText: 2024 Matthew Waters <matthew@centricular.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]
use std::sync::Once;

use libfuzzer_sys::fuzz_target;

#[macro_use]
extern crate tracing;
use tracing_subscriber::EnvFilter;

use stun_types::message::*;

#[derive(arbitrary::Arbitrary, Debug)]
struct DataAndCredentials<'data> {
    data: &'data [u8],
    credentials: MessageIntegrityCredentials,
}

pub fn debug_init() {
    static TRACING: Once = Once::new();

    TRACING.call_once(|| {
        if let Ok(filter) = EnvFilter::try_from_default_env() {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    });
}

fuzz_target!(|data_and_credentials: DataAndCredentials| {
    debug_init();
    let Ok(msg) = Message::from_bytes(data_and_credentials.data) else {
        return;
    };
    debug!("generated {:?}", msg);
    let integrity_result = msg.validate_integrity(&data_and_credentials.credentials);
    debug!("integrity result {:?}", integrity_result);
});
