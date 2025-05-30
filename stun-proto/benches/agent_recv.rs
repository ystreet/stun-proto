// Copyright (C) 2024 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use std::time::Instant;
use stun_proto::agent::StunAgent;
use stun_types::attribute::*;
use stun_types::message::{Message, MessageBuilder, BINDING};
use stun_types::TransportType;

fn builder_with_attribute(attr: &dyn AttributeWrite) -> MessageBuilder {
    let mut msg = Message::builder_request(BINDING);
    msg.add_attribute(attr).unwrap();
    msg
}

fn bench_agent_recv(c: &mut Criterion) {
    let local_addr = "127.0.0.1:1000".parse().unwrap();
    let remote_addr = "127.0.0.1:2000".parse().unwrap();
    let now = Instant::now();
    let software = Software::new("stun-proto").unwrap();

    let mut group = c.benchmark_group("Agent/Recv");

    group.throughput(criterion::Throughput::Bytes(
        builder_with_attribute(&software).build().len() as u64,
    ));
    let mut agent = StunAgent::builder(TransportType::Udp, local_addr).build();
    let builder = builder_with_attribute(&software);
    let _ = agent.send_request(builder, remote_addr, now).unwrap();

    group.bench_with_input("Message/Software", &software, move |b, software| {
        b.iter_batched(
            || builder_with_attribute(software).build(),
            |data| {
                let msg = Message::from_bytes(&data).unwrap();
                let _ = agent.handle_stun(msg, local_addr);
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

criterion_group!(agent_recv, bench_agent_recv);
criterion_main!(agent_recv);
