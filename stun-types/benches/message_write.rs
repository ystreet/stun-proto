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
    IntegrityAlgorithm, Message, MessageHeader, MessageIntegrityCredentials, MessageWriteMutSlice,
    MessageWriteVec, ShortTermCredentials, TransactionId, BINDING,
};
use stun_types::prelude::*;

fn build_with_attribute(attr: &dyn AttributeWrite) {
    let mut msg = Message::builder_request(
        BINDING,
        MessageWriteVec::with_capacity(MessageHeader::LENGTH + attr.padded_len()),
    );
    msg.add_attribute(attr).unwrap();
    let _data = msg.finish();
}

fn write_into_with_attribute(attr: &dyn AttributeWrite, dest: &mut [u8]) {
    let mut msg = Message::builder_request(BINDING, MessageWriteMutSlice::new(dest));
    msg.add_attribute(attr).unwrap();
    msg.finish();
}

fn bench_message_write(c: &mut Criterion) {
    let software = Software::new("stun-types").unwrap();
    let addr = "192.168.10.200:9876".parse().unwrap();
    let xor_mapped_address = XorMappedAddress::new(addr, TransactionId::generate());
    let nonce = Nonce::new("nonce").unwrap();
    let alt_server = AlternateServer::new(addr);
    let alt_domain = AlternateDomain::new("example.com");
    let unknown = UnknownAttributes::new(&[PasswordAlgorithms::TYPE]);
    let userhash = Userhash::new([0; 32]);
    let realm = Realm::new("realm").unwrap();
    let username = Username::new("abcd").unwrap();
    let short_term_integrity =
        MessageIntegrityCredentials::ShortTerm(ShortTermCredentials::new("password".to_owned()));

    let mut group = c.benchmark_group("Message/Build");

    group.throughput(criterion::Throughput::Bytes(
        MessageHeader::LENGTH as u64 + software.padded_len() as u64,
    ));
    group.bench_with_input(
        BenchmarkId::from_parameter("Software"),
        &software,
        |b, software| b.iter(|| build_with_attribute(software)),
    );
    let attrs: [&dyn AttributeWrite; 9] = [
        &software,
        &xor_mapped_address,
        &nonce,
        &alt_server,
        &alt_domain,
        &unknown,
        &userhash,
        &realm,
        &username,
    ];
    for i in 2..=attrs.len() {
        let len = MessageHeader::LENGTH as u64
            + attrs.iter().map(|attr| attr.padded_len()).sum::<usize>() as u64;
        group.throughput(criterion::Throughput::Bytes(len));
        group.bench_with_input(
            BenchmarkId::new("Attributes", i),
            &attrs[..i],
            |b, attrs| {
                b.iter(|| {
                    let mut msg =
                        Message::builder_request(BINDING, MessageWriteVec::with_capacity(128));
                    for attr in attrs {
                        msg.add_attribute(*attr).unwrap();
                    }
                    msg.finish()
                })
            },
        );
    }
    group.throughput(criterion::Throughput::Bytes(
        MessageHeader::LENGTH as u64 + xor_mapped_address.padded_len() as u64,
    ));
    group.bench_with_input(
        BenchmarkId::from_parameter("XorMappedAddress"),
        &xor_mapped_address,
        |b, xor_mapped_address| {
            b.iter(|| build_with_attribute(xor_mapped_address));
        },
    );
    group.throughput(criterion::Throughput::Bytes(
        MessageHeader::LENGTH as u64 + xor_mapped_address.padded_len() as u64 + 8,
    ));
    group.bench_with_input(
        BenchmarkId::from_parameter("XorMappedAddress+Fingerprint"),
        &xor_mapped_address,
        |b, xor_mapped_address| {
            b.iter(|| {
                let mut msg = Message::builder_request(BINDING, MessageWriteVec::with_capacity(32));
                msg.add_attribute(xor_mapped_address).unwrap();
                msg.add_fingerprint().unwrap();
                msg.finish();
            })
        },
    );
    group.throughput(criterion::Throughput::Bytes(
        MessageHeader::LENGTH as u64 + xor_mapped_address.padded_len() as u64 + 32,
    ));
    group.bench_with_input(
        BenchmarkId::from_parameter("XorMappedAddress+ShortTermIntegritySha1+Fingerprint"),
        &(&xor_mapped_address, &short_term_integrity),
        |b, &(xor_mapped_address, short_term_integrity)| {
            b.iter(|| {
                let mut msg = Message::builder_request(BINDING, MessageWriteVec::with_capacity(64));
                msg.add_attribute(xor_mapped_address).unwrap();
                msg.add_message_integrity(short_term_integrity, IntegrityAlgorithm::Sha1)
                    .unwrap();
                msg.add_fingerprint().unwrap();
                msg.finish();
            })
        },
    );
    group.throughput(criterion::Throughput::Bytes(
        MessageHeader::LENGTH as u64 + xor_mapped_address.padded_len() as u64 + 42,
    ));
    group.bench_with_input(
        BenchmarkId::from_parameter("XorMappedAddress+ShortTermIntegritySha256+Fingerprint"),
        &(&xor_mapped_address, &short_term_integrity),
        |b, &(xor_mapped_address, short_term_integrity)| {
            b.iter(|| {
                let mut msg = Message::builder_request(BINDING, MessageWriteVec::with_capacity(64));
                msg.add_attribute(xor_mapped_address).unwrap();
                msg.add_message_integrity(short_term_integrity, IntegrityAlgorithm::Sha256)
                    .unwrap();
                msg.add_fingerprint().unwrap();
                msg.finish();
            })
        },
    );
    group.finish();

    let mut group = c.benchmark_group("Message/WriteInto");
    let mut scratch = vec![0; 1 << 8];

    group.throughput(criterion::Throughput::Bytes(
        MessageHeader::LENGTH as u64 + software.padded_len() as u64,
    ));
    group.bench_with_input(
        BenchmarkId::from_parameter("Software"),
        &software,
        |b, software| b.iter(|| write_into_with_attribute(software, &mut scratch)),
    );

    for i in 2..=attrs.len() {
        group.bench_with_input(
            BenchmarkId::new("Attributes", i),
            &attrs[..i],
            |b, attrs| {
                b.iter(|| {
                    let mut msg =
                        Message::builder_request(BINDING, MessageWriteMutSlice::new(&mut scratch));
                    for attr in attrs {
                        msg.add_attribute(*attr).unwrap();
                    }
                    msg.finish();
                })
            },
        );
    }
    group.throughput(criterion::Throughput::Bytes(
        MessageHeader::LENGTH as u64 + xor_mapped_address.padded_len() as u64,
    ));
    group.bench_with_input(
        BenchmarkId::from_parameter("XorMappedAddress"),
        &xor_mapped_address,
        |b, xor_mapped_address| {
            b.iter(|| write_into_with_attribute(xor_mapped_address, &mut scratch));
        },
    );
    group.throughput(criterion::Throughput::Bytes(
        MessageHeader::LENGTH as u64 + xor_mapped_address.padded_len() as u64 + 8,
    ));
    group.bench_with_input(
        BenchmarkId::from_parameter("XorMappedAddress+Fingerprint"),
        &xor_mapped_address,
        |b, xor_mapped_address| {
            b.iter(|| {
                let mut msg =
                    Message::builder_request(BINDING, MessageWriteMutSlice::new(&mut scratch));
                msg.add_attribute(xor_mapped_address).unwrap();
                msg.add_fingerprint().unwrap();
                msg.finish();
            })
        },
    );
    group.throughput(criterion::Throughput::Bytes(
        MessageHeader::LENGTH as u64 + xor_mapped_address.padded_len() as u64 + 32,
    ));
    group.bench_with_input(
        BenchmarkId::from_parameter("XorMappedAddress+ShortTermIntegritySha1+Fingerprint"),
        &(&xor_mapped_address, &short_term_integrity),
        |b, &(xor_mapped_address, short_term_integrity)| {
            b.iter(|| {
                let mut msg =
                    Message::builder_request(BINDING, MessageWriteMutSlice::new(&mut scratch));
                msg.add_attribute(xor_mapped_address).unwrap();
                msg.add_message_integrity(short_term_integrity, IntegrityAlgorithm::Sha1)
                    .unwrap();
                msg.add_fingerprint().unwrap();
                msg.finish();
            })
        },
    );
    group.throughput(criterion::Throughput::Bytes(
        MessageHeader::LENGTH as u64 + xor_mapped_address.padded_len() as u64 + 42,
    ));
    group.bench_with_input(
        BenchmarkId::from_parameter("XorMappedAddress+ShortTermIntegritySha256+Fingerprint"),
        &(&xor_mapped_address, &short_term_integrity),
        |b, &(xor_mapped_address, short_term_integrity)| {
            b.iter(|| {
                let mut msg =
                    Message::builder_request(BINDING, MessageWriteMutSlice::new(&mut scratch));
                msg.add_attribute(xor_mapped_address).unwrap();
                msg.add_message_integrity(short_term_integrity, IntegrityAlgorithm::Sha256)
                    .unwrap();
                msg.add_fingerprint().unwrap();
                msg.finish();
            })
        },
    );
    group.finish();
}

criterion_group!(message_parse, bench_message_write);
criterion_main!(message_parse);
