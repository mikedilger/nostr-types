use crate::versioned::tag3::TagV3;

/// A tag on an Event
pub type Tag = TagV3;

/// The scope for tags that refer to events
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum Scope {
    /// Referring to the parent event (or NONE)
    Parent = 0,

    /// Referring to the root event
    Root = 1,
}

impl Scope {
    /// Same as Parent, but when no event is referenced at all it reads better
    pub const NONE: Scope = Scope::Parent;
}
