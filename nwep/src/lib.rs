//! idiomatic rust bindings for the web/1 protocol over quic (the nwep library).
//!
//! this crate is the safe, native face of libnwep. raw, unsafe declarations
//! live in the nwep-sys crate one layer down, and are reachable for anything
//! this layer does not yet wrap (no cliffs).
//!
//! today the crate covers the identity layer NW040200. the server, client,
//! dht, and trust layers are added slice by slice.
//!
//! # example
//!
//! ```
//! use nwep::Identity;
//!
//! let id = Identity::generate()?;
//! let name = id.node_id().to_base58();
//! assert!(id.node_id().verify(id.public_key()));
//! # Ok::<(), nwep::Error>(())
//! ```

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

mod address;
mod cache;
mod client;
mod dht;
mod error;
mod identity;
pub mod log;
mod logserver;
mod message;
// the managed runtime's portable readiness wait + cross-thread waker (eventfd +
// poll on unix, a loopback-udp self-pipe + WSAPoll on windows).
#[cfg(feature = "runtime")]
mod poll;
mod raw;
#[cfg(feature = "runtime")]
mod runtime;
mod server;
pub mod shamir;
#[cfg(feature = "trust")]
pub mod trust;
mod uri;
mod wire;

pub use address::Address;
pub use cache::{Cache, CacheStats};
pub use client::{
    Client, ClientBuilder, ClientMetrics, Connecting, RequestBuilder, RequestHandle, RequestId,
    Response, Stream,
};
pub use dht::{Bootstrap, Dht, DhtBuilder, DhtMetrics, Record};
pub use error::{Error, Result};
pub use identity::{Identity, NodeId};
pub use log::Log;
pub use logserver::{DispatchOutcome, LogServer};
pub use message::Headers;
pub use raw::RawSocket;
pub use server::{
    cid_shard_id, reuse_port_supported, ByteRange, CapturingResponder, Compression,
    DeferredResponder, Metrics, RangeOutcome, Reply, Request, Responder, Server, ServerBuilder,
};
pub use uri::Uri;
pub use wire::{Method, Status};

#[cfg(feature = "runtime")]
pub use runtime::{AsyncClient, AsyncRequestBuilder, AsyncStream, RunningServer};

/// returns the static version string of the linked nwep library.
pub fn version() -> &'static str {
    // SAFETY: nwep_version takes no pointer arguments; the function is always safe to call.
    let ptr = unsafe { nwep_sys::nwep_version() };
    // the library returns a static nul terminated ascii string, never null.
    // SAFETY: nwep_version returns a static nul-terminated string, never null.
    unsafe { core::ffi::CStr::from_ptr(ptr) }
        .to_str()
        .unwrap_or("unknown")
}

/// prelude re exports the handful of types reached for in almost every program.
///
/// glob import it to get started, use nwep::prelude::*
pub mod prelude {
    pub use crate::{
        Address, Bootstrap, Client, Dht, Error, Identity, Method, NodeId, Record, Reply, Request,
        Responder, Response, Result, Server, Status, Uri,
    };

    #[cfg(feature = "runtime")]
    pub use crate::{AsyncClient, RunningServer};
}
