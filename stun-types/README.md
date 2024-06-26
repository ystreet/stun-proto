[![Build status](https://github.com/ystreet/stun-proto/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/ystreet/stun-proto/actions)
[![codecov](https://codecov.io/gh/ystreet/stun-proto/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/stun-proto)
[![Dependencies](https://deps.rs/repo/github/ystreet/stun-proto/status.svg)](https://deps.rs/repo/github/ystreet/stun-proto)
[![crates.io](https://img.shields.io/crates/v/stun-types.svg)](https://crates.io/crates/stun-types)
[![docs.rs](https://docs.rs/stun-types/badge.svg)](https://docs.rs/stun-types)

# stun-types

Repository containing an implementation of STUN (RFC5389/RFC8489) protocol writing in
the [Rust programming language](https://www.rust-lang.org/).

## Goals

- Efficiency:
  - zero-copy parsing
  - no copies until the message is written.
- Support externally defined attributes easily. Only 3 traits required for an
  implementation, two of which are `From` and `TryFrom`.

## Relevant standards

 - [RFC5245](https://tools.ietf.org/html/rfc5245):
   Interactive Connectivity Establishment (ICE): A Protocol for Network Address
   Translator (NAT) Traversal for Offer/Answer Protocols
 - [RFC5389](https://tools.ietf.org/html/rfc5389):
   Session Traversal Utilities for NAT (STUN)
 - [RFC5766](https://tools.ietf.org/html/rfc5766):
   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
   Traversal Utilities for NAT (STUN)
 - [RFC5769](https://tools.ietf.org/html/rfc5769):
   Test Vectors for Session Traversal Utilities for NAT (STUN)
 - [RFC6156](https://tools.ietf.org/html/rfc6156):
   Traversal Using Relays around NAT (TURN) Extension for IPv6
 - [RFC8445](https://tools.ietf.org/html/rfc8445):
   Interactive Connectivity Establishment (ICE): A Protocol for Network Address
   Translator (NAT) Traversal
 - [RFC8489](https://tools.ietf.org/html/rfc8489):
   Session Traversal Utilities for NAT (STUN)
 - [RFC8656](https://tools.ietf.org/html/rfc8656):
   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
   Traversal Utilities for NAT (STUN)

## Examples

Have a look at the documentation at the crate root for some examples

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
   unless a specific attribute implement is required. This is not usually a big
   deal with most STUN messages but can become an issue with TURN usage and high
   bitrates transfers. Our goal is to perform no copies of the data unless
   necessary. `stun-format`, `stun_codec`, `stun-rs` fail this design goal.  The
   only other implementation I could find was `turn-rs` which contains a very
   small STUN implementation that is only enough for TURN usage.
3. Overly complicated with macros and additional traits. It shouldn't be
   necessary to implement STUN with complicated macros or `decoder`/`encoder`
   traits for messages and attributes. STUN is a relatively simple byte codec
   and does not require a complicated implementation. `stun-rs`, `stun_codec`,
   currently this design goal.
