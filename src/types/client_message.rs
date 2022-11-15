use super::{Event, Filters, SubscriptionId};

/// A message from a client to a relay
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientMessage {
    /// An event
    Event(Box<Event>),

    /// A subscription request
    Req(SubscriptionId, Vec<Filters>),

    /// A request to close a subscription
    Close(SubscriptionId),
}
