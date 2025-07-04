[![Build status](https://github.com/ystreet/stun-proto/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/ystreet/stun-proto/actions)
[![codecov](https://codecov.io/gh/ystreet/stun-proto/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/stun-proto)
[![Dependencies](https://deps.rs/repo/github/ystreet/stun-proto/status.svg)](https://deps.rs/repo/github/ystreet/stun-proto)
[![crates.io](https://img.shields.io/crates/v/stun-proto.svg)](https://crates.io/crates/stun-proto)
[![docs.rs](https://docs.rs/stun-proto/badge.svg)](https://docs.rs/stun-proto)

# stun-proto

Repository containing a sans-IO implementation of the STUN (RFC5389/RFC8489) protocol written in
the [Rust programming language](https://www.rust-lang.org/).

## Why sans-io?

A couple of reasons: reusability, and testability.

Without being bogged down in the details of how IO happens, the same sans-IO
implementation can be used without prescribing the IO pattern that an application
must follow. Instead, the application (or parent library) has much more freedom
in how bytes are transferred between peers. It's also possible to us a sans-IO
library in either a synchronous or within an asynchronous runtime.

sans-IO also allows easy testing of any specific state the sans-IO
implementation might find itself in. Combined with a comprehensive test-suite,
this provides assurance that the implementation behaves as expected under all
circumstances.

For other examples of sans-IO implementations, take a look at:
- [librice](https://github.com/ystreet/librice)
- [turn-proto](https://github.com/ystreet/turn-proto)
- [Quinn](https://github.com/quinn-rs/quinn/)
- https://sans-io.readthedocs.io/

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

