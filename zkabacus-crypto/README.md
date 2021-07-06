# zkabacus-crypto

This crate contains a public, misuse-resistant API for the cryptographic components of the zkAbacus protcol (the off-chain component of zkChannels), including documentation of how inputs must be checked in the non-cryptographic component. 
It _does not_ handle communication between participants or long-term storage across channels.

The [`customer`] and [`merchant`] modules describe state machines for each party. A
customer maintains state over the lifetime of a channel that allows it to correctly update the
channel balances, make payments, and close the channel. The merchant has a comparatively simple
state machine: it operates primarily as a server, atomically processing requests from
customers but never retaining (or even learning) information about specific channels.

Internally, this crate also defines zkAbacus-aware cryptographic types as wrappers around the basic
cryptographic primitives defined in `zkchannels-crypto`. Some of these types must be sent
between parties in the execution of zkAbacus; these are revealed publicly.

For more details, please build the Rust documentation:
```
$ cargo doc --all-features --no-deps --open
```