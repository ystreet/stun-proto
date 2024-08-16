// Copyright (C) 2024 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use stun_types::attribute::{Attribute, Nonce, RawAttribute, Software, XorMappedAddress};
use stun_types::message::TransactionId;

fn attr_to_raw<'a, A>(attr: A)
where
    A: Into<RawAttribute<'a>> + Sized,
{
    let raw = attr.into();
    let _bytes = raw.to_bytes();
}

fn bench_attribute_write(c: &mut Criterion) {
    let addr = "192.168.10.200:9876".parse().unwrap();

    let software = Software::new("stun-types").unwrap();
    c.bench_with_input(
        BenchmarkId::new("Attribute/Write", "Software"),
        &software,
        |b, software| b.iter(|| attr_to_raw(software)),
    );

    let xor_mapped_address = XorMappedAddress::new(addr, TransactionId::generate());
    c.bench_with_input(
        BenchmarkId::new("Attribute/Write", "XorMappedAddress"),
        &xor_mapped_address,
        |b, xor_mapped_address| b.iter(|| attr_to_raw(xor_mapped_address)),
    );

    let mut group = c.benchmark_group("Attribute/Write/Nonce");
    for n in [4, 64, 762] {
        let nonce = Nonce::new(&(0..n).fold(String::new(), |mut s, _c| {
            s.push('c');
            s
        }))
        .unwrap();
        group.throughput(criterion::Throughput::Bytes(nonce.length() as u64 + 4));
        group.bench_with_input(
            BenchmarkId::from_parameter(n.to_string()),
            &nonce,
            |b, nonce| b.iter(|| attr_to_raw(nonce)),
        );
    }
    group.finish();
}

criterion_group!(message_parse, bench_attribute_write);
criterion_main!(message_parse);
