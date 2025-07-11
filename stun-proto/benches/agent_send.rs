// Copyright (C) 2024 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::time::Instant;
use stun_proto::agent::StunAgent;
use stun_types::attribute::*;
use stun_types::message::{
    Message, MessageClass, MessageHeader, MessageType, MessageWriteVec, TransactionId, BINDING,
};
use stun_types::prelude::*;
use stun_types::TransportType;

fn bench_agent_send(c: &mut Criterion) {
    let local_addr = "127.0.0.1:1000".parse().unwrap();
    let remote_addr = "127.0.0.1:2000".parse().unwrap();
    let now = Instant::now();
    let software = Software::new("stun-proto").unwrap();

    let mut group = c.benchmark_group("Agent/Send");

    group.throughput(criterion::Throughput::Bytes(
        MessageHeader::LENGTH as u64 + software.padded_len() as u64 + 8,
    ));
    group.bench_with_input(
        "Message/Request/Software+Fingerprint",
        &software,
        move |b, software| {
            b.iter_batched(
                || {
                    let agent = StunAgent::builder(TransportType::Udp, local_addr).build();
                    let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
                    msg.add_attribute(software).unwrap();
                    msg.add_fingerprint().unwrap();
                    (agent, msg.finish())
                },
                |(mut agent, msg)| {
                    let _ = agent.send_request(msg, remote_addr, now).unwrap();
                },
                BatchSize::SmallInput,
            )
        },
    );

    group.throughput(criterion::Throughput::Bytes(
        MessageHeader::LENGTH as u64 + software.padded_len() as u64 + 8,
    ));
    group.bench_with_input(
        "Message/Indication/Software+Fingerprint",
        &software,
        move |b, software| {
            b.iter_batched(
                || {
                    let transaction_id = TransactionId::generate();
                    let mut msg = Message::builder(
                        MessageType::from_class_method(MessageClass::Indication, BINDING),
                        transaction_id,
                        MessageWriteVec::new(),
                    );
                    msg.add_attribute(software).unwrap();
                    msg.add_fingerprint().unwrap();
                    let agent = StunAgent::builder(TransportType::Udp, local_addr).build();
                    (agent, msg.finish())
                },
                |(mut agent, msg)| {
                    let _ = agent.send(msg, remote_addr, now).unwrap();
                },
                BatchSize::SmallInput,
            )
        },
    );

    for size in [32, 1024, 32768] {
        group.throughput(criterion::Throughput::Bytes(size as u64));
        let agent = StunAgent::builder(TransportType::Udp, local_addr).build();
        let data = vec![1; size];
        group.bench_function(BenchmarkId::new("Data", size), |b| {
            b.iter_batched(
                || data.clone(),
                |data| {
                    let _transmit = agent.send_data(data, remote_addr);
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(agent_send, bench_agent_send);
criterion_main!(agent_send);
