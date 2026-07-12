// the non-blocking client surface NW070000 NW060000. a client connects asynchronously
// (driven by hand, no blocking call), then submits two concurrent requests and
// polls both to completion from one tick loop. also covers request cancel and a
// connect over a caller-adopted socket. this is the event-loop client an embedder
// folds into epoll/io_uring.

// this exercises the driven layer by hand-rolling a unix poll loop, so it is a
// host (unix) test; the managed suites cover the same code paths on windows.
#![cfg(unix)]

use nwep::{Address, Client, Identity, Method, Server, Status};
use std::net::UdpSocket;
use std::os::fd::{IntoRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

fn now_ms() -> i64 {
    Instant::now().elapsed().as_millis() as i64
}

fn poll_readable(fd: RawFd, timeout_ms: u32) {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe {
        libc::poll(&mut pfd, 1, timeout_ms as libc::c_int);
    }
}

fn spawn_server() -> (
    nwep::NodeId,
    u16,
    Arc<AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    let id = Identity::generate().unwrap();
    let node = *id.node_id();
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let handle = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(id)
            .bind(Address::loopback(0))
            .on_request(|req, res| match req.path() {
                Some("/a") => res.ok(b"body-a"),
                Some("/b") => res.ok(b"body-b"),
                _ => res.not_found(),
            })
            .build()
            .unwrap();
        tx.send(server.local_port()).unwrap();
        while !stop_t.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let port = rx.recv_timeout(Duration::from_secs(3)).unwrap();
    (node, port, stop, handle)
}

#[test]
fn async_connect_then_concurrent_submit_poll() {
    let (node, port, stop, server_thread) = spawn_server();

    // drive the handshake to completion by hand.
    let connecting = Client::builder()
        .identity(Identity::generate().unwrap())
        .start_connect(&node, &Address::loopback(port))
        .unwrap();
    let mut client = None;
    for _ in 0..2000 {
        connecting.tick(now_ms()).unwrap();
        if connecting.poll().unwrap() {
            client = Some(connecting.into_client());
            break;
        }
        poll_readable(
            connecting.fd(),
            connecting.next_timeout(now_ms()).unwrap_or(20).min(20),
        );
    }
    let client = client.expect("async connect completed");
    assert!(client.is_alive());

    // submit two requests at once, then drive both to completion in one loop.
    let mut req_a = client.request(Method::Read, "/a").submit().unwrap();
    let mut req_b = client.request(Method::Read, "/b").submit().unwrap();
    assert_ne!(req_a.id(), req_b.id());

    let mut body_a = None;
    let mut body_b = None;
    for _ in 0..2000 {
        client.tick(now_ms()).unwrap();
        if body_a.is_none() {
            if let Some(r) = req_a.poll().unwrap() {
                body_a = Some(r.into_body());
            }
        }
        if body_b.is_none() {
            if let Some(r) = req_b.poll().unwrap() {
                body_b = Some(r.into_body());
            }
        }
        if body_a.is_some() && body_b.is_some() {
            break;
        }
        poll_readable(
            client.fd(),
            client.next_timeout(now_ms()).unwrap_or(20).min(20),
        );
    }
    assert_eq!(body_a.as_deref(), Some(&b"body-a"[..]));
    assert_eq!(body_b.as_deref(), Some(&b"body-b"[..]));

    // a submitted request can be cancelled before completion without error.
    let req_c = client.request(Method::Read, "/a").submit().unwrap();
    req_c.cancel();

    // req_a / req_b still borrow client, so let them (and client) drop at scope
    // end rather than moving client out from under the borrows.
    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
}

#[test]
fn connect_over_an_adopted_socket() {
    let (node, port, stop, server_thread) = spawn_server();

    // the embedder owns the udp socket and hands its fd to the client.
    let sock = UdpSocket::bind("[::1]:0").unwrap();
    let fd = sock.into_raw_fd();

    let client = Client::builder()
        .identity(Identity::generate().unwrap())
        .connect_fd(&node, &Address::loopback(port), fd)
        .unwrap();
    let resp = client.send(Method::Read, "/a", &[]).unwrap();
    assert_eq!(resp.status(), Some(Status::Ok));
    assert_eq!(resp.body(), b"body-a");

    drop(client);
    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
}
