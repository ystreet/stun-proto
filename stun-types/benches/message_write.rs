// Copyright (C) 2024 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use stun_types::attribute::*;
use stun_types::message::{
    IntegrityAlgorithm, Message, MessageBuilder, MessageIntegrityCredentials, ShortTermCredentials,
    TransactionId, BINDING,
};

fn builder_with_attribute<'a>(attr: impl Into<RawAttribute<'a>>) -> MessageBuilder<'a> {
    let mut msg = Message::builder_request(BINDING);
    msg.add_attribute(attr).unwrap();
    msg
}

fn build_with_attribute<'a>(attr: impl Into<RawAttribute<'a>>) {
    let mut msg = Message::builder_request(BINDING);
    msg.add_attribute(attr).unwrap();
    let _data = msg.build();
}

fn bench_message_write(c: &mut Criterion) {
    let software = Software::new("stun-types").unwrap();
    let addr = "192.168.10.200:9876".parse().unwrap();
    let xor_mapped_address = XorMappedAddress::new(addr, TransactionId::generate());
    let nonce = Nonce::new("nonce").unwrap();
    let alt_server = AlternateServer::new(addr);
    let alt_domain = AlternateDomain::new("example.com");
    let priority = Priority::new(100);
    let controlled = IceControlled::new(200);
    let controlling = IceControlling::new(300);
    let use_candidate = UseCandidate::new();
    let short_term_integrity =
        MessageIntegrityCredentials::ShortTerm(ShortTermCredentials::new("password".to_owned()));

    let mut group = c.benchmark_group("Message/Build");

    group.throughput(criterion::Throughput::Bytes(
        builder_with_attribute(&software).build().len() as u64,
    ));
    group.bench_with_input(
        BenchmarkId::from_parameter("Software"),
        &software,
        |b, software| b.iter(|| build_with_attribute(software)),
    );
    group.bench_with_input(
        BenchmarkId::from_parameter("Attributes/9"),
        &(
            &software,
            &xor_mapped_address,
            &nonce,
            &alt_server,
            &alt_domain,
            &priority,
            &controlled,
            &controlling,
            &use_candidate,
        ),
        |b, attrs| {
            b.iter(|| {
                let mut msg = builder_with_attribute(attrs.0);
                msg.add_attribute(attrs.1).unwrap();
                msg.add_attribute(attrs.2).unwrap();
                msg.add_attribute(attrs.3).unwrap();
                msg.add_attribute(attrs.4).unwrap();
                msg.add_attribute(attrs.5).unwrap();
                msg.add_attribute(attrs.6).unwrap();
                msg.add_attribute(attrs.7).unwrap();
                msg.add_attribute(attrs.8).unwrap();
                msg.build();
            })
        },
    );
    group.bench_with_input(
        BenchmarkId::from_parameter("XorMappedAddress"),
        &xor_mapped_address,
        |b, xor_mapped_address| {
            b.iter(|| build_with_attribute(xor_mapped_address));
        },
    );
    group.bench_with_input(
        BenchmarkId::from_parameter("XorMappedAddress+Fingerprint"),
        &xor_mapped_address,
        |b, xor_mapped_address| {
            b.iter(|| {
                let mut msg = builder_with_attribute(xor_mapped_address);
                msg.add_fingerprint().unwrap();
                msg.build();
            })
        },
    );
    group.bench_with_input(
        BenchmarkId::from_parameter("XorMappedAddress+ShortTermIntegritySha1+Fingerprint"),
        &(&xor_mapped_address, &short_term_integrity),
        |b, &(xor_mapped_address, short_term_integrity)| {
            b.iter(|| {
                let mut msg = builder_with_attribute(xor_mapped_address);
                msg.add_message_integrity(short_term_integrity, IntegrityAlgorithm::Sha1)
                    .unwrap();
                msg.add_fingerprint().unwrap();
                msg.build();
            })
        },
    );
    group.bench_with_input(
        BenchmarkId::from_parameter("XorMappedAddress+ShortTermIntegritySha256+Fingerprint"),
        &(&xor_mapped_address, &short_term_integrity),
        |b, &(xor_mapped_address, short_term_integrity)| {
            b.iter(|| {
                let mut msg = builder_with_attribute(xor_mapped_address);
                msg.add_message_integrity(short_term_integrity, IntegrityAlgorithm::Sha256)
                    .unwrap();
                msg.add_fingerprint().unwrap();
                msg.build();
            })
        },
    );
    group.finish();
}

criterion_group!(message_parse, bench_message_write);
criterion_main!(message_parse);
