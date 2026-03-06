// Copyright (C) 2026 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use stun_proto::auth::ShortTermAuth;
use stun_types::attribute::*;
use stun_types::message::{
    IntegrityAlgorithm, Message, MessageWriteVec, ShortTermCredentials, ValidateError, BINDING,
};
use stun_types::prelude::*;

fn request(software: &Software) -> MessageWriteVec {
    let mut msg = Message::builder_request(BINDING, MessageWriteVec::with_capacity(64));
    msg.add_attribute(software).unwrap();
    msg
}

fn bench_auth_short_term(c: &mut Criterion) {
    let software = Software::new("stun-proto").unwrap();
    let credentials = ShortTermCredentials::new("some-password".to_string());
    let wrong_credentials = ShortTermCredentials::new("another-password".to_string());

    let mut group = c.benchmark_group("Auth/ShortTerm");

    let mut auth = ShortTermAuth::new();

    group.throughput(criterion::Throughput::Elements(1));
    group.bench_with_input(
        "None/Request/Software/Sign",
        &software,
        move |b, software| {
            b.iter_batched(
                || request(software),
                |msg| auth.sign_outgoing_message(msg),
                BatchSize::SmallInput,
            )
        },
    );

    let mut auth = ShortTermAuth::new();
    let msg = request(&software);
    let msg = msg.finish();
    let msg = Message::from_bytes(&msg).unwrap();

    group.bench_with_input("None/Request/Software/Validate", &msg, move |b, msg| {
        b.iter(|| {
            assert!(matches!(auth.validate_incoming_message(msg), Ok(None)));
        })
    });

    let mut auth = ShortTermAuth::new();
    auth.set_credentials(credentials.clone(), IntegrityAlgorithm::Sha1);

    group.bench_with_input(
        "Sha1/Request/Software/Sign",
        &software,
        move |b, software| {
            b.iter_batched(
                || request(software),
                |msg| auth.sign_outgoing_message(msg),
                BatchSize::SmallInput,
            )
        },
    );

    let mut auth = ShortTermAuth::new();
    auth.set_credentials(credentials.clone(), IntegrityAlgorithm::Sha1);

    let mut msg = request(&software);
    msg.add_message_integrity(&credentials.clone().into(), IntegrityAlgorithm::Sha1)
        .unwrap();
    let msg = msg.finish();
    let msg = Message::from_bytes(&msg).unwrap();

    group.bench_with_input("Sha1/Request/Software/Validate", &msg, move |b, msg| {
        b.iter(|| {
            assert!(matches!(
                auth.validate_incoming_message(msg),
                Ok(Some(IntegrityAlgorithm::Sha1))
            ));
        })
    });

    let mut auth = ShortTermAuth::new();
    auth.set_credentials(credentials.clone(), IntegrityAlgorithm::Sha1);

    let mut msg = request(&software);
    msg.add_message_integrity(&wrong_credentials.clone().into(), IntegrityAlgorithm::Sha1)
        .unwrap();
    let msg = msg.finish();
    let msg = Message::from_bytes(&msg).unwrap();

    group.bench_with_input(
        "Sha1/Request/Software/Validate/Incorrect",
        &msg,
        move |b, msg| {
            b.iter(|| {
                assert!(matches!(
                    auth.validate_incoming_message(msg),
                    Err(ValidateError::IntegrityFailed)
                ));
            })
        },
    );

    let mut auth = ShortTermAuth::new();
    auth.set_credentials(credentials.clone(), IntegrityAlgorithm::Sha256);

    group.bench_with_input(
        "Sha256/Request/Software/Sign",
        &software,
        move |b, software| {
            b.iter_batched(
                || request(software),
                |msg| auth.sign_outgoing_message(msg),
                BatchSize::SmallInput,
            )
        },
    );

    let mut auth = ShortTermAuth::new();
    auth.set_credentials(credentials.clone(), IntegrityAlgorithm::Sha256);

    let mut msg = request(&software);
    msg.add_message_integrity(&credentials.clone().into(), IntegrityAlgorithm::Sha256)
        .unwrap();
    let msg = msg.finish();
    let msg = Message::from_bytes(&msg).unwrap();

    group.bench_with_input("Sha256/Request/Software/Validate", &msg, move |b, msg| {
        b.iter(|| {
            assert!(matches!(
                auth.validate_incoming_message(msg),
                Ok(Some(IntegrityAlgorithm::Sha256))
            ));
        })
    });

    let mut auth = ShortTermAuth::new();
    auth.set_credentials(credentials.clone(), IntegrityAlgorithm::Sha256);

    let mut msg = request(&software);
    msg.add_message_integrity(
        &wrong_credentials.clone().into(),
        IntegrityAlgorithm::Sha256,
    )
    .unwrap();
    let msg = msg.finish();
    let msg = Message::from_bytes(&msg).unwrap();

    group.bench_with_input(
        "Sha256/Request/Software/Validate/Incorrect",
        &msg,
        move |b, msg| {
            b.iter(|| {
                assert!(matches!(
                    auth.validate_incoming_message(msg),
                    Err(ValidateError::IntegrityFailed)
                ));
            })
        },
    );

    group.finish();
}

criterion_group!(auth_short_term, bench_auth_short_term);
criterion_main!(auth_short_term);
