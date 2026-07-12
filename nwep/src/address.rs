//! nwep address, an ipv6 socket address NW110300.
//!
//! Address is the opaque transport address a server binds and a client dials.
//! web/1 is ipv6 only, so an ipv4 address is carried in the ::ffff:a.b.c.d
//! mapped form. it is a plain value, cheap to copy. construct one from a part
//! (loopback, a std SocketAddr, raw bytes) and read its port back.

use crate::error::{Error, Result};
use core::fmt;
use core::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use core::str::FromStr;
use nwep_sys as sys;

/// Address is an opaque ipv6 socket address, the bind or dial target of a node.
#[derive(Clone, Copy)]
pub struct Address(sys::nwep_address);

impl Address {
    /// builds the ::1 loopback address at port.
    pub fn loopback(port: u16) -> Address {
        let mut a = sys::nwep_address { opaque: [0; 32] };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_address_loopback(&mut a, port) };
        Address(a)
    }

    /// builds the :: wildcard address (all interfaces) at port.
    pub fn wildcard(port: u16) -> Address {
        let mut a = sys::nwep_address { opaque: [0; 32] };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_address_wildcard(&mut a, port) };
        Address(a)
    }

    /// builds the ::ffff:a.b.c.d ipv4 mapped address at port NW110300.
    pub fn ipv4_mapped(a: u8, b: u8, c: u8, d: u8, port: u16) -> Address {
        let mut addr = sys::nwep_address { opaque: [0; 32] };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_address_ipv4_mapped(&mut addr, a, b, c, d, port) };
        Address(addr)
    }

    /// builds an address from 16 raw ipv6 bytes (network order) and a port.
    pub fn from_bytes(addr: [u8; 16], port: u16) -> Address {
        let mut out = sys::nwep_address { opaque: [0; 32] };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_address_from_bytes(&mut out, addr.as_ptr(), port) };
        Address(out)
    }

    /// returns the host order port of this address.
    pub fn port(&self) -> u16 {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_address_get_port(&self.0) }
    }

    /// borrows the raw c address, for handing to a lower layer (no-cliffs).
    // used by the server and client slices to pass a bind or dial target down.
    #[allow(dead_code)]
    pub(crate) fn as_raw(&self) -> &sys::nwep_address {
        &self.0
    }

    /// wraps a raw c address returned by a lower layer (for example a dht record).
    pub(crate) fn from_raw(raw: sys::nwep_address) -> Address {
        Address(raw)
    }
}

impl From<SocketAddrV6> for Address {
    fn from(s: SocketAddrV6) -> Address {
        Address::from_bytes(s.ip().octets(), s.port())
    }
}

impl From<SocketAddr> for Address {
    fn from(s: SocketAddr) -> Address {
        match s {
            SocketAddr::V6(v6) => v6.into(),
            SocketAddr::V4(v4) => {
                let o = v4.ip().octets();
                Address::ipv4_mapped(o[0], o[1], o[2], o[3], v4.port())
            }
        }
    }
}

impl From<(Ipv6Addr, u16)> for Address {
    fn from((ip, port): (Ipv6Addr, u16)) -> Address {
        Address::from_bytes(ip.octets(), port)
    }
}

impl FromStr for Address {
    type Err = Error;

    /// parses a socket address like the ::1 loopback or a v4 host, each with a port.
    ///
    /// an ipv4 address becomes its ::ffff:a.b.c.d mapped form NW110300.
    ///
    /// returns the parsed [Address].
    /// errors [Error::ConfigInvalid] when s is not a valid socket address.
    fn from_str(s: &str) -> Result<Address> {
        s.parse::<SocketAddr>()
            .map(Address::from)
            .map_err(|_| Error::ConfigInvalid)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // the address bytes are opaque NW110300, so only the port is shown.
        f.debug_struct("Address")
            .field("port", &self.port())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_carry_the_port() {
        assert_eq!(Address::loopback(443).port(), 443);
        assert_eq!(Address::wildcard(80).port(), 80);
        assert_eq!(Address::ipv4_mapped(127, 0, 0, 1, 7000).port(), 7000);
        assert_eq!(Address::from_bytes([0; 16], 9).port(), 9);
    }

    #[test]
    fn parses_v6_and_v4_socket_strings() {
        assert_eq!("[::1]:443".parse::<Address>().unwrap().port(), 443);
        assert_eq!("127.0.0.1:8080".parse::<Address>().unwrap().port(), 8080);
        assert!("not an address".parse::<Address>().is_err());
    }
}
