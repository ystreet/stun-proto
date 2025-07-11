// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg(not(tarpaulin))]

use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::{SocketAddr, UdpSocket};
use std::process::exit;
use std::str::FromStr;

use tracing::{info, trace};

use stun_types::attribute::*;
use stun_types::message::*;
use stun_types::TransportType;

fn usage() {
    println!("stunclient [protocol] [address:port]");
    println!();
    println!("\tprotocol: can be either \'udp\' or \'tcp\'");
}

fn parse_response(response: Message) -> Result<(), std::io::Error> {
    if Message::check_attribute_types(
        &response,
        &[
            XorMappedAddress::TYPE,
            Fingerprint::TYPE,
            AttributeType::new(1),
        ],
        &[XorMappedAddress::TYPE],
        MessageWriteVec::new(),
    )
    .is_some()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Required attributes not found in response",
        ));
    }
    if response.has_class(MessageClass::Success) {
        // presence checked by check_attribute_types() above
        let mapped_address = response.attribute::<XorMappedAddress>().unwrap();
        let visible_addr = mapped_address.addr(response.transaction_id());
        println!("found visible address {:?}", visible_addr);
        Ok(())
    } else if response.has_class(MessageClass::Error) {
        println!("got error response {:?}", response);
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Error response",
        ))
    } else {
        println!("got unknown response {:?}", response);
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Unknown response",
        ))
    }
}

fn tcp_message(out: MessageWriteVec, to: SocketAddr) -> Result<(), std::io::Error> {
    let mut socket = TcpStream::connect(to).unwrap();

    info!("generated to {:?}", out);
    let buf = out.finish();
    trace!("generated to {:?}", buf);
    socket.write_all(&buf)?;
    let mut buf = [0; 1500];
    let mut offset = 0;
    let msg;
    loop {
        let amt = socket.read(&mut buf[offset..])?;
        let data = &buf[..offset + amt];
        if amt == 0 {
            trace!("got {:?}", data);
            msg = Message::from_bytes(data).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid message: {e:?}"),
                )
            })?;
            break;
        }
        match MessageHeader::from_bytes(data) {
            Ok(header) => {
                if header.data_length() as usize + MessageHeader::LENGTH > 1500 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Response data is too large to receive",
                    ));
                }
                if header.data_length() as usize + MessageHeader::LENGTH < offset + amt {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Response data is too large for message",
                    ));
                }
            }
            Err(StunParseError::NotStun) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Did not receive a STUN response",
                ))
            }
            Err(e) => trace!("parsing STUN message header produced: \'{e}\'"),
        }
        offset += amt;
    }
    info!(
        "received from {:?} to {:?} {}",
        socket.peer_addr().unwrap(),
        socket.local_addr().unwrap(),
        msg
    );

    parse_response(msg)
}

fn udp_message(out: MessageWriteVec, to: SocketAddr) -> Result<(), std::io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;

    info!("generated to {:?}", out);
    let buf = out.finish();
    trace!("generated to {:?}", buf);
    socket.send_to(&buf, to)?;
    let mut buf = [0; 1500];
    let (amt, src) = socket.recv_from(&mut buf)?;
    let buf = &buf[..amt];
    trace!("got {:?}", buf);
    let msg = Message::from_bytes(buf)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid message"))?;
    info!(
        "got from {:?} to {:?} {}",
        src,
        socket.local_addr().unwrap(),
        msg
    );

    parse_response(msg)
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

fn main() -> std::io::Result<()> {
    init_logs();

    let args: Vec<String> = env::args().collect();
    let proto = if args.len() > 1 {
        if args[1] == "udp" {
            TransportType::Udp
        } else if args[1] == "tcp" {
            TransportType::Tcp
        } else {
            usage();
            exit(1);
        }
    } else {
        TransportType::Udp
    };

    let to: SocketAddr = SocketAddr::from_str(if args.len() > 2 {
        &args[2]
    } else {
        "127.0.0.1:3478"
    })
    .unwrap();

    println!("sending STUN message over {:?} to {}", proto, to);
    let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
    msg.add_fingerprint().unwrap();

    match proto {
        TransportType::Udp => udp_message(msg, to),
        TransportType::Tcp => tcp_message(msg, to),
    }
}
