// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg(not(tarpaulin))]

use std::fmt::Display;
use std::net::SocketAddr;

use std::io::{self, Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::str::FromStr;
use std::time::Instant;

use tracing::{debug, error, info, warn};

use stun_types::attribute::*;
use stun_types::message::*;

use stun_proto::agent::{HandleStunReply, StunAgent, StunError};

fn warn_on_err<T, E>(res: Result<T, E>, default: T) -> T
where
    E: Display,
{
    match res {
        Ok(v) => v,
        Err(e) => {
            warn!("{}", e);
            default
        }
    }
}

fn handle_binding_request(msg: &Message, from: SocketAddr) -> Result<Vec<u8>, StunError> {
    if let Some(error_msg) =
        Message::check_attribute_types(msg, &[Fingerprint::TYPE], &[], MessageWriteVec::new())
    {
        return Ok(error_msg.finish());
    }

    let mut response = Message::builder_success(msg, MessageWriteVec::new());
    let xor_addr = XorMappedAddress::new(from, msg.transaction_id());
    response.add_attribute(&xor_addr)?;
    response.add_fingerprint()?;
    Ok(response.finish())
}

fn handle_incoming_data(
    data: &[u8],
    from: SocketAddr,
    stun_agent: &mut StunAgent,
) -> Option<(Vec<u8>, SocketAddr)> {
    let msg = Message::from_bytes(data).ok()?;
    let reply = stun_agent.handle_stun(msg, from);
    match reply {
        HandleStunReply::Drop => None,
        HandleStunReply::ValidatedStunResponse(_response)
        | HandleStunReply::UnvalidatedStunResponse(_response) => {
            error!("received unexpected STUN response from {from}!");
            None
        }
        HandleStunReply::IncomingStun(msg) => {
            info!("received from {}: {}", from, msg);
            if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                match handle_binding_request(&msg, from) {
                    Ok(response) => {
                        info!("sending response to {}: {:?}", from, response);
                        return Some((response, from));
                    }
                    Err(err) => warn!("error: {}", err),
                }
            } else {
                let mut response = Message::builder_error(&msg, MessageWriteVec::new());
                let error = ErrorCode::new(400, "Bad Request").unwrap();
                response.add_attribute(&error).unwrap();
                return Some((response.finish(), from));
            }
            None
        }
    }
}

fn init_logs() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;
    let level_filter = std::env::var("STUN_LOG")
        .ok()
        .and_then(|var| var.parse::<tracing_subscriber::filter::Targets>().ok())
        .unwrap_or(tracing_subscriber::filter::Targets::new().with_default(tracing::Level::ERROR));
    let registry = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_file(true)
            .with_line_number(true)
            .with_level(true)
            .with_target(false)
            .with_writer(std::io::stderr)
            .with_filter(level_filter),
    );
    tracing::subscriber::set_global_default(registry).unwrap()
}

fn main() -> io::Result<()> {
    init_logs();

    let args: Vec<String> = std::env::args().collect();
    let local_addr: SocketAddr = SocketAddr::from_str(if args.len() > 1 {
        &args[1]
    } else {
        "127.0.0.1:3478"
    })
    .unwrap();
    std::thread::spawn({
        move || {
            let udp_socket = UdpSocket::bind(local_addr).unwrap();
            let mut udp_stun_agent =
                StunAgent::builder(stun_proto::types::TransportType::Udp, local_addr).build();

            loop {
                let mut data = [0; 1500];
                let (len, from) = warn_on_err(udp_socket.recv_from(&mut data), (0, local_addr));
                if let Some((response, to)) =
                    handle_incoming_data(&data[..len], from, &mut udp_stun_agent)
                {
                    warn_on_err(udp_socket.send_to(&response, to), 0);
                }
            }
        }
    });

    let tcp_listener = TcpListener::bind(local_addr)?;
    let mut incoming = tcp_listener.incoming();
    while let Some(Ok(mut stream)) = incoming.next() {
        std::thread::spawn(move || {
            let remote_addr = stream.peer_addr().unwrap();
            let mut tcp_stun_agent =
                StunAgent::builder(stun_proto::types::TransportType::Tcp, local_addr)
                    .remote_addr(remote_addr)
                    .build();
            // TODO: handle split writes/reads and request timeouts.
            let mut data = [0; 1500];
            let size = warn_on_err(stream.read(&mut data), 0);
            if size == 0 {
                debug!("TCP connection with {remote_addr} closed");
                return;
            }
            if let Some((response, to)) =
                handle_incoming_data(&data[..size], remote_addr, &mut tcp_stun_agent)
            {
                if let Ok(transmit) = tcp_stun_agent.send(response, to, Instant::now()) {
                    warn_on_err(stream.write_all(&transmit.data), ());
                }
            }
            // XXX: Assumes that the stun packet arrives in a single packet
            stream.shutdown(std::net::Shutdown::Read).unwrap();
        });
    }

    Ok(())
}
