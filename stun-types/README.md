[![Build status](https://github.com/ystreet/stun-proto/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/ystreet/stun-proto/actions)
[![codecov](https://codecov.io/gh/ystreet/stun-proto/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/stun-proto)
[![Dependencies](https://deps.rs/repo/github/ystreet/stun-proto/status.svg)](https://deps.rs/repo/github/ystreet/stun-proto)
[![crates.io](https://img.shields.io/crates/v/stun-types.svg)](https://crates.io/crates/stun-types)
[![docs.rs](https://docs.rs/stun-types/badge.svg)](https://docs.rs/stun-types)

# stun-types

Repository containing an implementation of STUN (RFC5389/RFC8489) protocol writing in
the [Rust programming language](https://www.rust-lang.org/). The
[turn-types](https://docs.rs/turn-types/latest/turn_types/) crate uses `stun-types` to
implement STUN attributes for TURN.

## Goals

- Efficiency:
  - Zero-copy parsing
  - Attributes are directly written to the Message when added.
- Extensible:
  - Supports externally defined attributes easily. Four self-contained traits are
    required for an reading and writing `Attribute`s.  See
    [defining your own attribute](https://docs.rs/stun-types/latest/stun_types/attribute/index.html#defining-your-own-attribute)
    in the documentation for more details.
  - Message writing can be controlled through the `MessageWrite` trait. But if
    you don't need the complexity, a `Vec<u8>`-based implementation is also available.

## Relevant standards

 - [x] [RFC5389](https://tools.ietf.org/html/rfc5389):
   Session Traversal Utilities for NAT (STUN)
 - [x] [RFC5769](https://tools.ietf.org/html/rfc5769):
   Test Vectors for Session Traversal Utilities for NAT (STUN)
 - [x] [RFC8489](https://tools.ietf.org/html/rfc8489):
   Session Traversal Utilities for NAT (STUN)

If you are looking for attribute implementations related to TURN, have a look at
the [turn-types](https://docs.rs/turn-types/latest/turn_types/) crate which uses
`stun-types` to implement the required attributes for TURN.

 - [RFC5766](https://tools.ietf.org/html/rfc5766):
   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
   Traversal Utilities for NAT (STUN)
 - [RFC6062](https://tools.ietf.org/html/rfc6062):
   Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations
 - [RFC6156](https://tools.ietf.org/html/rfc6156):
   Traversal Using Relays around NAT (TURN) Extension for IPv6
 - [RFC8656](https://tools.ietf.org/html/rfc8656):
   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
   Traversal Utilities for NAT (STUN)

If you are looking for attribute implementation of ICE, have a look at
[rice-stun-types](https://docs.rs/rice-stun-types/latest/rice-stun-types).

 - [RFC5245](https://tools.ietf.org/html/rfc5245):
   Interactive Connectivity Establishment (ICE): A Protocol for Network Address
   Translator (NAT) Traversal for Offer/Answer Protocols
 - [RFC8445](https://tools.ietf.org/html/rfc8445):
   Interactive Connectivity Establishment (ICE): A Protocol for Network Address
   Translator (NAT) Traversal

## Examples

Have a look at the documentation at the crate root for some examples.

## Why not use `stun_codec`, `stun-format`, `stun-rs`, or 'insert crate here'?

Existing STUN crates suffer from one of a few of shortcomings.

1. Encoding attributes as enum's rather than as a trait. Using a trait for
   attributes allows external code to implement their own attributes and is thus
   not limited to what the crate implements.  A trait-based approach also allows
   us to add attribute implementations without requiring breaking semver.
   `rust-stun-coder` and `stun-format` fall into this category.  While we do aim
   to eventually support all the STUN attributes currently defined by the IANA
   and in various RFCs, we are also not going to force a user to use our
   implementations (except for integrity and fingerprint attributes).
2. Non-zero copy parsing. i.e. taking some input data and making no copies
   unless a specific attribute implementation requires. This is not usually a big
   deal with most STUN attributes as attributes are usually very small however
   this can become a significant issue with TURN usage where a STUN attribute
   contains the data sent and received. Our goal is to perform no copies of the
   data unless necessary. `stun-format`, `stun_codec`, `stun-rs` fail this
   design goal. The only other implementation I could find at the time of
   writing was `turn-rs` which contains a very minimal STUN implementation
   that is only sufficient for TURN usage.
3. Overly complicated with macros and many traits. It shouldn't be
   necessary to implement STUN with complicated macros or `decoder`/`encoder`
   traits for messages and attributes. STUN is a relatively simple byte codec
   and does not require a complicated implementation. `stun-rs`, `stun_codec`,
   currently fail this design goal.
