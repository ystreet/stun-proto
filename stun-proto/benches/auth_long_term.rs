// Copyright (C) 2026 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::net::SocketAddr;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use stun_proto::auth::{
    AuthErrorReason, LongTermClientAuth, LongTermServerAuth, LongTermValidation,
};
use stun_proto::Instant;
use stun_types::attribute::*;
use stun_types::message::{
    IntegrityAlgorithm, LongTermCredentials, Message, MessageWriteVec, BINDING,
};
use stun_types::prelude::*;

fn request(software: &Software) -> MessageWriteVec {
    let mut msg = Message::builder_request(BINDING, MessageWriteVec::with_capacity(64));
    msg.add_attribute(software).unwrap();
    msg
}

fn server_unauthorized_response(
    server: &mut LongTermServerAuth,
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

fn server_authorized_response(
    server: &mut LongTermServerAuth,
    msg: &Message<'_>,
    client_addr: SocketAddr,
    user: &str,
) -> MessageWriteVec {
    let response = Message::builder_success(msg, MessageWriteVec::new());
    server
        .sign_outgoing_message(response, user, client_addr)
        .unwrap()
}

fn initial_auth(
    client: &mut LongTermClientAuth,
    server: &mut LongTermServerAuth,
    from: SocketAddr,
    now: Instant,
    software: &Software,
) {
    let request = client
        .sign_outgoing_message(request(software))
        .unwrap()
        .finish();
    let request = Message::from_bytes(&request).unwrap();
    assert!(matches!(
        server
            .validate_incoming_message(&request, from, now),
        Err(e) if e.reason() == AuthErrorReason::Unauthorized
    ));
    let response = server_unauthorized_response(server, &request, from).finish();
    let response = Message::from_bytes(&response).unwrap();
    assert!(matches!(
        client.validate_incoming_message(&response),
        Ok(LongTermValidation::ResendRequest(None))
    ));
}

fn complete_auth(
    client: &mut LongTermClientAuth,
    server: &mut LongTermServerAuth,
    from: SocketAddr,
    now: Instant,
    software: &Software,
) {
    let request = client
        .sign_outgoing_message(request(software))
        .unwrap()
        .finish();
    let request = Message::from_bytes(&request).unwrap();
    assert!(matches!(
        server
            .validate_incoming_message(&request, from, now)
            .unwrap(),
        LongTermValidation::Validated(IntegrityAlgorithm::Sha1)
    ));
    let response = server_authorized_response(
        server,
        &request,
        from,
        client.credentials().unwrap().username(),
    )
    .finish();
    let response = Message::from_bytes(&response).unwrap();
    assert!(matches!(
        client.validate_incoming_message(&response),
        Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
    ));
}

fn bench_auth_long_term(c: &mut Criterion) {
    let client_addr = "10.0.0.1:1".parse().unwrap();
    let now = Instant::ZERO;
    let software = Software::new("stun-proto").unwrap();
    let credentials = LongTermCredentials::new("user".to_string(), "password".to_string());
    let wrong_password = LongTermCredentials::new("user".to_string(), "wrong-password".to_string());
    let wrong_username =
        LongTermCredentials::new("another-user".to_string(), "password".to_string());
    let realm = "realm".to_string();

    let mut group = c.benchmark_group("Auth/LongTerm");

    group.throughput(criterion::Throughput::Elements(1));
    group.bench_with_input(
        "Client/Request/Software/Sign",
        &(&credentials, &realm, &software),
        move |b, &(credentials, realm, software)| {
            b.iter_batched(
                || {
                    let mut client = LongTermClientAuth::new();
                    client.set_credentials(credentials.clone());
                    let mut server = LongTermServerAuth::new(realm.clone());
                    server.add_user(credentials.clone());
                    initial_auth(&mut client, &mut server, client_addr, now, software);
                    (request(software), client)
                },
                |(msg, mut client)| {
                    let msg = client.sign_outgoing_message(msg).unwrap();
                    (msg, client)
                },
                BatchSize::SmallInput,
            )
        },
    );

    group.bench_with_input(
        "Server/Request/Software/Validate",
        &(&credentials, &realm, &software),
        move |b, &(credentials, realm, software)| {
            b.iter_batched(
                || {
                    let mut client = LongTermClientAuth::new();
                    client.set_credentials(credentials.clone());
                    let mut server = LongTermServerAuth::new(realm.clone());
                    server.add_user(credentials.clone());
                    initial_auth(&mut client, &mut server, client_addr, now, software);
                    let msg = client
                        .sign_outgoing_message(request(software))
                        .unwrap()
                        .finish();
                    (msg, server)
                },
                |(msg, mut server)| {
                    let incoming = Message::from_bytes(&msg).unwrap();
                    assert!(matches!(
                        server
                            .validate_incoming_message(&incoming, client_addr, now)
                            .unwrap(),
                        LongTermValidation::Validated(IntegrityAlgorithm::Sha1)
                    ));
                    (msg, server)
                },
                BatchSize::SmallInput,
            )
        },
    );

    group.bench_with_input(
        "Server/Request/Software/Validate/WrongUsername",
        &(&wrong_username, &credentials, &realm, &software),
        move |b, &(wrong_credentials, credentials, realm, software)| {
            b.iter_batched(
                || {
                    let mut client = LongTermClientAuth::new();
                    client.set_credentials(wrong_credentials.clone());
                    let mut server = LongTermServerAuth::new(realm.clone());
                    server.add_user(credentials.clone());
                    initial_auth(&mut client, &mut server, client_addr, now, software);
                    let msg = client
                        .sign_outgoing_message(request(software))
                        .unwrap()
                        .finish();
                    (msg, server)
                },
                |(msg, mut server)| {
                    let incoming = Message::from_bytes(&msg).unwrap();
                    assert!(matches!(
                        server
                            .validate_incoming_message(&incoming, client_addr, now),
                        Err(e) if e.reason() == AuthErrorReason::Unauthorized
                    ));
                    (msg, server)
                },
                BatchSize::SmallInput,
            )
        },
    );

    group.bench_with_input(
        "Server/Request/Software/Validate/WrongPassword",
        &(&wrong_password, &credentials, &realm, &software),
        move |b, &(wrong_credentials, credentials, realm, software)| {
            b.iter_batched(
                || {
                    let mut client = LongTermClientAuth::new();
                    client.set_credentials(wrong_credentials.clone());
                    let mut server = LongTermServerAuth::new(realm.clone());
                    server.add_user(credentials.clone());
                    initial_auth(&mut client, &mut server, client_addr, now, software);
                    let msg = client
                        .sign_outgoing_message(request(software))
                        .unwrap()
                        .finish();
                    (msg, server)
                },
                |(msg, mut server)| {
                    let incoming = Message::from_bytes(&msg).unwrap();
                    assert!(matches!(
                        server
                            .validate_incoming_message(&incoming, client_addr, now),
                        Err(e) if e.reason() == AuthErrorReason::Unauthorized
                    ));
                    (msg, server)
                },
                BatchSize::SmallInput,
            )
        },
    );

    group.bench_with_input(
        "Server/Request/Software/Sign",
        &(&credentials, &realm, &software),
        move |b, &(credentials, realm, software)| {
            b.iter_batched(
                || {
                    let mut client = LongTermClientAuth::new();
                    client.set_credentials(credentials.clone());
                    let mut server = LongTermServerAuth::new(realm.clone());
                    server.add_user(credentials.clone());
                    initial_auth(&mut client, &mut server, client_addr, now, software);
                    complete_auth(&mut client, &mut server, client_addr, now, software);
                    let msg = request(software);
                    (msg, server)
                },
                |(msg, mut server)| {
                    let msg = server
                        .sign_outgoing_message(msg, credentials.username(), client_addr)
                        .unwrap();
                    (msg, server)
                },
                BatchSize::SmallInput,
            )
        },
    );

    group.bench_with_input(
        "Client/Request/Software/Validate",
        &(&credentials, &realm, &software),
        move |b, &(credentials, realm, software)| {
            b.iter_batched(
                || {
                    let mut client = LongTermClientAuth::new();
                    client.set_credentials(credentials.clone());
                    let mut server = LongTermServerAuth::new(realm.clone());
                    server.add_user(credentials.clone());
                    initial_auth(&mut client, &mut server, client_addr, now, software);
                    complete_auth(&mut client, &mut server, client_addr, now, software);
                    let msg = request(software);
                    let msg = server
                        .sign_outgoing_message(msg, credentials.username(), client_addr)
                        .unwrap()
                        .finish();
                    (msg, client)
                },
                |(msg, mut client)| {
                    let incoming = Message::from_bytes(&msg).unwrap();
                    assert!(matches!(
                        client.validate_incoming_message(&incoming),
                        Ok(LongTermValidation::Validated(IntegrityAlgorithm::Sha1))
                    ));
                    (msg, client)
                },
                BatchSize::SmallInput,
            )
        },
    );

    group.finish();
}

criterion_group!(auth_long_term, bench_auth_long_term);
criterion_main!(auth_long_term);
