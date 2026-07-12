//! poll is the managed runtime's portable readiness wait + cross-thread waker.
//!
//! the managed owner loop (runtime.rs) sleeps until one of three things happens:
//! a datagram arrives on the c socket, a transport timer is due, or the async side
//! enqueues new work. it does that by waiting on the socket *and* a Waker the async
//! side signals. the primitives differ per platform  -  a linux eventfd + poll on
//! unix, a loopback-udp self-pipe + WSAPoll on windows  -  but the shape is the
//! same, so runtime.rs stays platform-agnostic. only the "runtime" feature pulls
//! this in.
//!
//! the windows path hand-writes its winsock externs, matching how nwep-sys declares
//! every c symbol (no third-party crate for the os boundary).

use crate::raw::RawSocket;

#[cfg(unix)]
pub(crate) use unix::{wait_readable, wait_readable2, Waker};
#[cfg(windows)]
pub(crate) use windows::{wait_readable, wait_readable2, Waker};

// unix: an eventfd waker + poll() readiness wait
#[cfg(unix)]
mod unix {
    use super::RawSocket;

    /// Waker is a linux eventfd the async side signals to break the owner loop out
    /// of its wait the instant new work is enqueued (no poll latency, no busy spin).
    pub(crate) struct Waker(RawSocket);

    impl Waker {
        /// creates a non-blocking, close-on-exec eventfd waker.
        pub(crate) fn new() -> std::io::Result<Waker> {
            // SAFETY: eventfd takes an initial count and flags, returns an fd or -1.
            let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Waker(fd))
        }

        /// wakes the owner loop, incrementing the eventfd counter.
        pub(crate) fn wake(&self) {
            let v: u64 = 1;
            // SAFETY: writing 8 bytes to an eventfd is the documented wake op.
            unsafe {
                libc::write(self.0, (&v as *const u64).cast(), 8);
            }
        }

        /// drains pending wakeups so the next wait blocks again.
        pub(crate) fn drain(&self) {
            let mut v: u64 = 0;
            // SAFETY: read drains the counter; nonblocking, so it stops at EAGAIN.
            while unsafe { libc::read(self.0, (&mut v as *mut u64).cast(), 8) } > 0 {}
        }

        /// returns the waker's raw handle, to wait on alongside the socket.
        pub(crate) fn raw(&self) -> RawSocket {
            self.0
        }
    }

    impl Drop for Waker {
        fn drop(&mut self) {
            // SAFETY: the fd is owned and not used after this.
            unsafe {
                libc::close(self.0);
            }
        }
    }

    /// waits up to timeout_ms for the socket to become readable, best effort.
    pub(crate) fn wait_readable(fd: RawSocket, timeout_ms: u32) {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a valid single pollfd for the duration of the call.
        unsafe {
            libc::poll(&mut pfd, 1, timeout_ms as libc::c_int);
        }
    }

    /// waits up to timeout_ms for either handle to become readable, best effort.
    pub(crate) fn wait_readable2(a: RawSocket, b: RawSocket, timeout_ms: u32) {
        let mut fds = [
            libc::pollfd {
                fd: a,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: b,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: a valid two-entry pollfd array for the duration of the call.
        unsafe {
            libc::poll(fds.as_mut_ptr(), 2, timeout_ms as libc::c_int);
        }
    }
}

// windows: a loopback-udp self-pipe waker + WSAPoll readiness wait
#[cfg(windows)]
mod windows {
    use super::RawSocket;
    use std::sync::Once;

    // minimal winsock declarations, hand-written like the nwep-sys c externs. a
    // windows SOCKET is a `usize`-wide handle; INVALID_SOCKET is all-ones.
    const AF_INET: i32 = 2;
    const SOCK_DGRAM: i32 = 2;
    const FIONBIO: i32 = -2_147_195_266; // 0x8004667E, sets non-blocking mode.
    const POLLRDNORM: i16 = 0x0100; // normal data may be read without blocking.
    const INVALID_SOCKET: usize = usize::MAX;
    const WINSOCK_VERSION: u16 = 0x0202; // request winsock 2.2.

    #[repr(C)]
    struct WsaPollFd {
        fd: usize,
        events: i16,
        revents: i16,
    }

    // sockaddr_in layout - family + (network-order) port + (network-order) addr + padding.
    #[repr(C)]
    struct SockaddrIn {
        family: u16,
        port: u16,
        addr: u32,
        zero: [u8; 8],
    }

    // WSADATA is roughly 400 bytes. we only need a buffer to receive it, never to read it.
    #[repr(C)]
    struct WsaData {
        _opaque: [u8; 408],
    }

    #[link(name = "ws2_32")]
    extern "system" {
        fn WSAStartup(version: u16, data: *mut WsaData) -> i32;
        fn socket(af: i32, ty: i32, protocol: i32) -> usize;
        fn bind(s: usize, addr: *const SockaddrIn, len: i32) -> i32;
        fn connect(s: usize, addr: *const SockaddrIn, len: i32) -> i32;
        fn getsockname(s: usize, addr: *mut SockaddrIn, len: *mut i32) -> i32;
        fn ioctlsocket(s: usize, cmd: i32, argp: *mut u32) -> i32;
        fn send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32;
        fn recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32;
        fn closesocket(s: usize) -> i32;
        #[link_name = "WSAPoll"]
        fn wsa_poll(fds: *mut WsaPollFd, nfds: u32, timeout: i32) -> i32;
    }

    /// initializes winsock once per process (idempotent; refcounted by the os).
    fn ensure_winsock() {
        static START: Once = Once::new();
        START.call_once(|| {
            let mut data = WsaData { _opaque: [0; 408] };
            // SAFETY: WSAStartup fills the provided WSADATA buffer; we never read it.
            unsafe {
                WSAStartup(WINSOCK_VERSION, &mut data);
            }
        });
    }

    /// Waker is a loopback udp socket connected to itself, the windows self-pipe:
    /// the async side sends a byte to wake the owner loop out of its WSAPoll.
    pub(crate) struct Waker(usize);

    impl Waker {
        /// creates a non-blocking loopback-udp waker socket bound + connected to self.
        pub(crate) fn new() -> std::io::Result<Waker> {
            ensure_winsock();
            // SAFETY: each call follows the documented winsock socket lifecycle; every early return closes the socket it opened.
            unsafe {
                let s = socket(AF_INET, SOCK_DGRAM, 0);
                if s == INVALID_SOCKET {
                    return Err(std::io::Error::last_os_error());
                }
                let mut addr = SockaddrIn {
                    family: AF_INET as u16,
                    port: 0, // 0 = let the os pick an ephemeral port.
                    addr: u32::from_ne_bytes([127, 0, 0, 1]), // 127.0.0.1, network order.
                    zero: [0; 8],
                };
                let len = core::mem::size_of::<SockaddrIn>() as i32;
                if bind(s, &addr, len) != 0 {
                    let e = std::io::Error::last_os_error();
                    closesocket(s);
                    return Err(e);
                }
                // learn the bound ephemeral port, then connect to self so send()
                // targets this same socket.
                let mut got = len;
                if getsockname(s, &mut addr, &mut got) != 0 || connect(s, &addr, len) != 0 {
                    let e = std::io::Error::last_os_error();
                    closesocket(s);
                    return Err(e);
                }
                let mut nonblocking: u32 = 1;
                ioctlsocket(s, FIONBIO, &mut nonblocking);
                Ok(Waker(s))
            }
        }

        /// wakes the owner loop by sending a byte to the self-connected socket.
        pub(crate) fn wake(&self) {
            let b: u8 = 1;
            // SAFETY: a 1-byte send on an owned connected udp socket.
            unsafe {
                send(self.0, &b, 1, 0);
            }
        }

        /// drains pending wake bytes so the next WSAPoll blocks again.
        pub(crate) fn drain(&self) {
            let mut buf = [0u8; 64];
            // SAFETY: nonblocking recv into an owned buffer; stops at WSAEWOULDBLOCK.
            while unsafe { recv(self.0, buf.as_mut_ptr(), buf.len() as i32, 0) } > 0 {}
        }

        /// returns the waker's raw socket, to wait on alongside the c socket.
        pub(crate) fn raw(&self) -> RawSocket {
            self.0 as RawSocket
        }
    }

    impl Drop for Waker {
        fn drop(&mut self) {
            // SAFETY: the socket is owned and not used after this.
            unsafe {
                closesocket(self.0);
            }
        }
    }

    /// waits up to timeout_ms for the socket to become readable, best effort.
    pub(crate) fn wait_readable(fd: RawSocket, timeout_ms: u32) {
        let mut pfd = WsaPollFd {
            fd: fd as usize,
            events: POLLRDNORM,
            revents: 0,
        };
        // SAFETY: a valid single WSAPOLLFD for the duration of the call.
        unsafe {
            wsa_poll(&mut pfd, 1, timeout_ms as i32);
        }
    }

    /// waits up to timeout_ms for either socket to become readable, best effort.
    pub(crate) fn wait_readable2(a: RawSocket, b: RawSocket, timeout_ms: u32) {
        let mut fds = [
            WsaPollFd {
                fd: a as usize,
                events: POLLRDNORM,
                revents: 0,
            },
            WsaPollFd {
                fd: b as usize,
                events: POLLRDNORM,
                revents: 0,
            },
        ];
        // SAFETY: a valid two-entry WSAPOLLFD array for the duration of the call.
        unsafe {
            wsa_poll(fds.as_mut_ptr(), 2, timeout_ms as i32);
        }
    }
}
