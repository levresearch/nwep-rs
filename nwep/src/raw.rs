//! raw is the cross-platform raw socket handle the library hands the caller NW070000.
//!
//! the c abi returns the udp socket as an intptr_t and adopts one as a
//! uintptr_t, which is a posix fd on unix and a windows SOCKET. RawSocket is
//! the native handle type on each platform, so [crate::Server]::fd, [crate::Client]::fd, and the
//! adopt-socket builders (from_fd, connect_fd) stay portable  -  a caller
//! registers it with their own poller (epoll/kqueue/IOCP) in the driven loop.

/// RawSocket is the platform's raw udp socket handle, a posix fd on unix.
#[cfg(unix)]
pub type RawSocket = std::os::fd::RawFd;

/// RawSocket is the platform's raw udp socket handle, a windows SOCKET.
#[cfg(windows)]
pub type RawSocket = std::os::windows::io::RawSocket;

/// converts the intptr_t the library returns from a *_fd getter to a RawSocket.
///
/// the value is a small valid descriptor in practice, so the per-platform cast is
/// lossless for any real socket.
pub(crate) fn from_c(handle: isize) -> RawSocket {
    handle as RawSocket
}

/// converts a RawSocket to the uintptr_t the adopt-socket builders take NW000017.
pub(crate) fn to_c(socket: RawSocket) -> usize {
    socket as usize
}
