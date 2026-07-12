// a minimal driven server, the rust echo of the sandbox nwserve app. binds a
// node, answers read /hello with a body, and runs its own tick loop. prints the
// node_id and port so a client (or the round_trip test) can reach it.
//
// run it, then in another shell point a web/1 client at the printed address.

use nwep::{Address, Identity, Server};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn main() -> nwep::Result<()> {
    let server = Server::builder()
        .identity(Identity::generate()?)
        .bind(Address::loopback(0))
        .on_request(|req, res| match req.path() {
            Some("/hello") => res.ok(b"hi from nwep rust\n"),
            _ => res.not_found(),
        })
        .build()?;

    println!("serving on [::1]:{}", server.local_port());
    println!("node {}", server.node_id()?);
    println!("answering read /hello, ctrl-c to stop");

    // driven loop: the caller owns it. a real reactor would wait on server.fd()
    // until server.next_timeout(); this example just ticks at a steady cadence.
    loop {
        server.tick(now_ms())?;
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}
