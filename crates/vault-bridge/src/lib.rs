//! Arca's loopback bridge, in one place for the app and both of its clients:
//! the browser's native-messaging host and `arca`. [`proto`] is what crosses
//! the socket; [`auth`] is how each side proves the other holds the token.

pub mod auth;
pub mod proto;

/// The bridge protocol the app and its clients speak. Bump it when an existing
/// request or response changes shape in a way an older client would get
/// wrong; a new request type, or a field an older client ignores, is not such
/// a change.
pub const PROTOCOL: u32 = 3;
