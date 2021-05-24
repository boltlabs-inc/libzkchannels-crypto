/// Keys and parameters used by the customer throughout the lifetime of a merchant node, across all its zkChannels.
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
pub struct Config;

/// The output of a merchant operation.
#[derive(Debug)]
pub struct Output<Status, Keep, Send> {
    /// The new `Status` of the merchant channel.
    pub state: Status,
    /// The data the merchant must `Keep` in storage.
    pub keep: Keep,
    /// The data the merchant must `Send` to the customer.
    pub send: Send,
}

/// A merchant node that is ready to receive customer requests.
#[derive(Debug)]
pub struct Ready {
    config: Config,
}

pub mod establish;
