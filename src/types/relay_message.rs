use super::{Event, Id, SubscriptionId};

/// A message from a relay to a client
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayMessage {
    /// An event matching a subscription
    Event(SubscriptionId, Box<Event>),

    /// A human readable notice for errors and other information
    Notice(String),

    /// End of subscribed events notification
    Eose(SubscriptionId),

    /// Used to notify clients if an event was successuful
    Ok(Id, bool, String),
}
