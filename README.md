[![Build status](https://github.com/ystreet/stun-proto/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/ystreet/stun-proto/actions)
[![codecov](https://codecov.io/gh/ystreet/stun-proto/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/stun-proto)
[![Dependencies](https://deps.rs/repo/github/ystreet/stun-proto/status.svg)](https://deps.rs/repo/github/ystreet/stun-proto)
[![crates.io](https://img.shields.io/crates/v/stun-proto.svg)](https://crates.io/crates/stun-proto)
[![docs.rs](https://docs.rs/stun-proto/badge.svg)](https://docs.rs/stun-proto)

# stun-proto

Repository containing an implementation of STUN (RFC5389/RFC8489) protocol writing in
the [Rust programming language](https://www.rust-lang.org/).

## Relevant standards

 - [RFC5389](https://tools.ietf.org/html/rfc5389):
   Session Traversal Utilities for NAT (STUN)
 - [RFC8489](https://tools.ietf.org/html/rfc8489):
   Session Traversal Utilities for NAT (STUN)

## Structure

### [stun-types](https://github.com/ystreet/stun-proto/tree/main/stun-types)

Contains parsers and writing implementations for STUN messages and attributes.

### [stun-proto](https://github.com/ystreet/stun-proto/tree/main/stun-proto)

`stun-proto` builds on top of `stun-types` and implements some of the
STUN protocol requirements when communicating with a peer. It does this using a
sans-IO API and thus does no networking calls of its own.
