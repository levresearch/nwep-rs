//! nwep dht, the discovery layer that resolves a node_id to an address NW110000.
//!
//! Dht is a kademlia node that shares a [Server]'s udp socket and answers the
//! one question the protocol has no dns for, where does this node_id live. attach
//! one to a server, join the network through a [Bootstrap] contact, then announce
//! this node or look others up. the borrow ties a Dht to its server, so the
//! compiler keeps the server alive for as long as the dht NW110900.
//!
//! the headline use is [crate::ClientBuilder::connect_by_node_id], which resolves
//! a node_id through the dht and connects in one call NW110800.

use crate::address::Address;
use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::server::Server;
use core::ffi::c_char;
use core::marker::PhantomData;
use core::ptr;
use nwep_sys as sys;

// bootstrap contact NW110900

/// Bootstrap is a known peer the dht contacts at startup to join NW110900.
///
/// it is a node_id at an address, parsed from the node_id@host:port text form (host bracketed for ipv6) or built from parts. plain data, cheap to copy and send.
#[derive(Clone, Copy)]
pub struct Bootstrap(sys::nwep_bootstrap_entry);

impl Bootstrap {
    /// parses the node_id@host:port text form (host bracketed for ipv6) bootstrap entry NW110900.
    ///
    /// returns the parsed [Bootstrap].
    /// errors [Error::ProtoInvalidHeader] when the text is malformed.
    pub fn parse(input: &str) -> Result<Bootstrap> {
        let mut entry = sys::nwep_bootstrap_entry {
            node_id: sys::nwep_node_id {
                bytes: [0; sys::NWEP_NODEID_SIZE],
            },
            addr: sys::nwep_address { opaque: [0; 32] },
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_dht_parse_bootstrap(&mut entry, input.as_ptr().cast::<c_char>(), input.len())
        })?;
        Ok(Bootstrap(entry))
    }

    /// builds a bootstrap contact from a node_id and its address.
    pub fn new(node_id: &NodeId, addr: &Address) -> Bootstrap {
        Bootstrap(sys::nwep_bootstrap_entry {
            node_id: node_id.raw(),
            addr: *addr.as_raw(),
        })
    }
}

impl core::str::FromStr for Bootstrap {
    type Err = Error;
    fn from_str(s: &str) -> Result<Bootstrap> {
        Bootstrap::parse(s)
    }
}

// record + metrics NW110300

/// Record is a resolved discovery record binding a node to an address NW110300.
#[derive(Clone, Copy)]
pub struct Record(sys::nwep_dht_record);

impl Record {
    /// returns the node_id this record names.
    pub fn node_id(&self) -> NodeId {
        NodeId::from_bytes(self.0.node_id.bytes)
    }

    /// returns the address the node was found at.
    pub fn address(&self) -> Address {
        Address::from_raw(self.0.addr)
    }

    /// borrows the node's ed25519 public key.
    pub fn public_key(&self) -> &[u8; sys::NWEP_PUBKEY_SIZE] {
        &self.0.pubkey
    }

    /// returns the record's sequence number, higher is newer NW110600.
    pub fn seq(&self) -> u64 {
        self.0.seq
    }

    /// returns the record's unix-seconds timestamp NW110300.
    pub fn timestamp(&self) -> u64 {
        self.0.timestamp
    }
}

/// DhtMetrics is a snapshot of a dht's traffic counters.
#[derive(Clone, Copy, Debug, Default)]
pub struct DhtMetrics {
    /// datagrams the dht sent.
    pub datagrams_sent: u64,
    /// datagrams the dht received, including malformed ones it dropped.
    pub datagrams_received: u64,
    /// udp payload bytes the dht sent.
    pub bytes_sent: u64,
    /// udp payload bytes the dht received.
    pub bytes_received: u64,
}

// dht builder NW110900 NWG0300

/// DhtBuilder attaches a [Dht] to a server NWG0300.
///
/// add one or more bootstrap contacts (at least one is required), optionally the
/// last announced sequence number, then call .attach().
pub struct DhtBuilder<'srv> {
    server: &'srv Server,
    bootstraps: Vec<sys::nwep_bootstrap_entry>,
    initial_seq: u64,
}

impl<'srv> DhtBuilder<'srv> {
    /// adds a bootstrap contact to seed the routing table NW110900.
    pub fn bootstrap(mut self, contact: Bootstrap) -> Self {
        self.bootstraps.push(contact.0);
        self
    }

    /// adds many bootstrap contacts at once.
    pub fn bootstraps(mut self, contacts: impl IntoIterator<Item = Bootstrap>) -> Self {
        self.bootstraps.extend(contacts.into_iter().map(|b| b.0));
        self
    }

    /// sets the last announced record sequence to resume from NW110600.
    ///
    /// pass the value persisted from a previous run so a fresh announce supersedes
    /// the old record. the default is 0, correct for a brand new node.
    pub fn initial_seq(mut self, seq: u64) -> Self {
        self.initial_seq = seq;
        self
    }

    /// attaches the dht to the server, reusing its socket NW110900.
    ///
    /// returns the attached [Dht], borrowing the server for its lifetime.
    /// errors [Error::ConfigMissing] when no bootstrap contact was added, and
    /// [Error::ConfigInvalid] when initial_seq is at its maximum.
    pub fn attach(self) -> Result<Dht<'srv>> {
        if self.bootstraps.is_empty() {
            return Err(Error::ConfigMissing);
        }
        let mut raw: *mut sys::nwep_dht = ptr::null_mut();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_dht_attach(
                &mut raw,
                self.server.as_ptr(),
                self.bootstraps.as_ptr(),
                self.bootstraps.len(),
                self.initial_seq,
            )
        })?;
        Ok(Dht {
            raw,
            _server: PhantomData,
        })
    }
}

// dht NW110000

/// Dht is a discovery node sharing a [Server]'s socket NW110000. see module docs.
///
/// it is single threaded like the server it borrows, which the raw pointer field
/// encodes as !Send and !Sync NWG0900.
pub struct Dht<'srv> {
    raw: *mut sys::nwep_dht,
    _server: PhantomData<&'srv Server>,
}

impl<'srv> Dht<'srv> {
    /// starts a [DhtBuilder] attached to server.
    pub fn builder(server: &'srv Server) -> DhtBuilder<'srv> {
        DhtBuilder {
            server,
            bootstraps: Vec::new(),
            initial_seq: 0,
        }
    }

    /// joins the network by pinging every bootstrap contact NW110900.
    ///
    /// the responses arrive on later server and dht ticks. now_secs is a
    /// unix-seconds clock.
    ///
    /// returns unit on success.
    /// errors a transport [Error] when the pings cannot be sent.
    pub fn join(&self, now_secs: u64) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_dht_bootstrap(self.raw, now_secs) })
    }

    /// publishes a signed record binding this node to service_addr NW110700.
    ///
    /// re-call within the republish interval so the record does not expire.
    ///
    /// returns unit on success.
    /// errors a transport or [Error::ConfigInvalid] when the announce fails.
    pub fn announce(&self, service_addr: &Address, now_secs: u64) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_dht_announce(self.raw, service_addr.as_raw(), now_secs) })
    }

    /// begins an iterative lookup for target's discovery record NW110800.
    ///
    /// returns immediately, poll [Dht::lookup_result] after later ticks. the
    /// blocking [crate::ClientBuilder::connect_by_node_id] wraps this whole dance.
    ///
    /// returns unit on success.
    /// errors a transport [Error] when the lookup cannot start.
    pub fn start_lookup(&self, target: &NodeId, now_secs: u64) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_dht_start_lookup(self.raw, &target.raw(), now_secs) })
    }

    /// reads target's resolved record if one has been observed NW110800.
    ///
    /// returns some record on a hit, or none when the lookup has not resolved.
    pub fn lookup_result(&self, target: &NodeId) -> Option<Record> {
        let mut out = sys::nwep_dht_record {
            node_id: sys::nwep_node_id {
                bytes: [0; sys::NWEP_NODEID_SIZE],
            },
            addr: sys::nwep_address { opaque: [0; 32] },
            pubkey: [0; sys::NWEP_PUBKEY_SIZE],
            seq: 0,
            timestamp: 0,
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe { sys::nwep_dht_lookup_result(self.raw, &target.raw(), &mut out) };
        if rc == 0 {
            Some(Record(out))
        } else {
            None
        }
    }

    /// advances dht timers, refresh, expiry, and retransmit NW110000.
    ///
    /// call it alongside [Server::tick]. now_secs is a unix-seconds clock,
    /// distinct from the server's monotonic millisecond clock.
    ///
    /// returns unit on success.
    /// errors a transport [Error] when the tick fails.
    pub fn tick(&self, now_secs: u64) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_dht_tick(self.raw, now_secs) })
    }

    /// returns milliseconds until the next dht timer, or none when idle.
    ///
    /// fold it into the same poll wait as [Server::next_timeout], taking the
    /// minimum of the two. none means no dht timer is pending.
    pub fn next_timeout(&self, now_secs: u64) -> Option<u32> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let ms = unsafe { sys::nwep_dht_next_timeout_ms(self.raw, now_secs) };
        if ms < 0 {
            None
        } else {
            Some(ms as u32)
        }
    }

    /// returns a snapshot of this dht's traffic counters.
    ///
    /// the dht shares the server's socket but its datagrams bypass the server
    /// metrics, so this is the only complete view of dht traffic.
    pub fn metrics(&self) -> DhtMetrics {
        let mut m = sys::nwep_dht_metrics {
            datagrams_sent: 0,
            datagrams_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        };
        // a non null handle and out never errors, so the code is ignored.
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_dht_metrics_get(self.raw, &mut m) };
        DhtMetrics {
            datagrams_sent: m.datagrams_sent,
            datagrams_received: m.datagrams_received,
            bytes_sent: m.bytes_sent,
            bytes_received: m.bytes_received,
        }
    }

    /// borrows the raw c dht handle, the escape hatch to the sys layer NWG0200.
    pub fn as_ptr(&self) -> *mut sys::nwep_dht {
        self.raw
    }
}

impl Drop for Dht<'_> {
    fn drop(&mut self) {
        // detaches and frees the dht, the borrowed server's socket stays open.
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_dht_close(self.raw) };
    }
}
