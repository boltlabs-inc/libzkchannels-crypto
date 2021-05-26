//! Cryptographic routines for establishing and paying on a channel.
/// Keys and parameters used by the customer throughout the lifetime of a zkChannel.
#[derive(Debug, Clone, Copy)]
pub struct Config {}

pub mod establish;
pub mod pay;
