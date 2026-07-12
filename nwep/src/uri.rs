//! nwep uri, a parsed web:// address NW040400.
//!
//! Uri is the web://nodeid:port/path form (port optional) that a client dials. it carries the
//! [NodeId] to resolve, the port, and the request path. it owns its path, so it
//! outlives the string it was parsed from.

use crate::error::{Error, Result};
use crate::identity::NodeId;
use core::ffi::c_char;
use core::str::FromStr;
use nwep_sys as sys;

/// Uri is a parsed web:// address, a node_id plus a port and request path NW040400.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uri {
    node_id: NodeId,
    port: u16,
    path: String,
}

impl Uri {
    /// parses the web://nodeid:port/path form (port optional) uri NW040400.
    ///
    /// the path is validated for the spec 4.4 hazards (no "..", no encoded
    /// separators) and copied out, so the returned Uri does not borrow input.
    /// an omitted port resolves to the protocol default.
    ///
    /// returns the parsed [Uri].
    /// errors [Error::ProtoInvalidMessage] when the scheme is wrong, and
    /// [Error::ProtoInvalidHeader] when the authority or path is malformed.
    pub fn parse(input: &str) -> Result<Uri> {
        let mut out = sys::nwep_uri {
            node_id: sys::nwep_node_id {
                bytes: [0; sys::NWEP_NODEID_SIZE],
            },
            port: 0,
            path: core::ptr::null(),
            path_len: 0,
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_uri_parse(&mut out, input.as_ptr().cast::<c_char>(), input.len())
        })?;
        // path borrows input, which is alive for this call, so copy it now.
        let path = if out.path.is_null() || out.path_len == 0 {
            String::new()
        } else {
            // SAFETY: buf is sized to len as returned by the probe call above.
            let bytes = unsafe { core::slice::from_raw_parts(out.path.cast::<u8>(), out.path_len) };
            core::str::from_utf8(bytes)
                .map_err(|_| Error::ProtoInvalidMessage)?
                .to_owned()
        };
        Ok(Uri {
            node_id: NodeId::from_bytes(out.node_id.bytes),
            port: out.port,
            path,
        })
    }

    /// borrows the node_id this uri addresses.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// returns the port, the protocol default when the uri omitted one.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// borrows the request path, including any query string NW040400.
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl FromStr for Uri {
    type Err = Error;
    fn from_str(s: &str) -> Result<Uri> {
        Uri::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    #[test]
    fn parses_node_id_port_and_path() {
        let id = Identity::generate().unwrap();
        let b58 = id.node_id().to_base58();

        let uri = Uri::parse(&format!("web://{b58}:443/hello")).unwrap();
        assert_eq!(uri.node_id(), id.node_id());
        assert_eq!(uri.port(), 443);
        assert_eq!(uri.path(), "/hello");
    }

    #[test]
    fn omitted_port_resolves_to_a_default() {
        let id = Identity::generate().unwrap();
        let b58 = id.node_id().to_base58();
        let uri = Uri::parse(&format!("web://{b58}/")).unwrap();
        assert_eq!(uri.node_id(), id.node_id());
        assert!(uri.port() != 0); // some non-zero default
        assert_eq!(uri.path(), "/");
    }

    #[test]
    fn rejects_a_bad_scheme_and_a_traversal_path() {
        assert!(Uri::parse("http://example/").is_err());
        let id = Identity::generate().unwrap();
        let b58 = id.node_id().to_base58();
        assert!(Uri::parse(&format!("web://{b58}/../etc")).is_err());
    }
}
