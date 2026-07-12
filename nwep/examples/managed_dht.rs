// the managed dht quickstart. stand up a server whose runtime owns an attached
// dht, then resolve a peer by node_id alone  -  all async, no tick loop. the
// headline "no dns" capability with the L2 on-ramp. requires the default
// "runtime" feature. a rendezvous node, an announcing peer, and a resolver all
// run .serve().await with .dht(...) in this one process.

use nwep::{Address, Bootstrap, Client, Identity, Method, Server, Status};
use std::time::Duration;

// each node binds a distinct 127.0.0.x loopback ip (ipv4-mapped) so the three do
// not share one per-source-ip dht budget.
fn lo(octet: u8, port: u16) -> Address {
    Address::ipv4_mapped(127, 0, 0, octet, port)
}

#[tokio::main]
async fn main() -> nwep::Result<()> {
    let (r_port, a_port, g_port) = (29401u16, 29402, 29403);

    // the rendezvous node: self-bootstraps and routes.
    let r_id = Identity::generate()?;
    let r_node = *r_id.node_id();
    let _r = Server::builder()
        .identity(r_id)
        .bind(lo(1, r_port))
        .dht([Bootstrap::new(&r_node, &lo(1, r_port))])
        .serve()
        .await?;
    let r_contact = Bootstrap::new(&r_node, &lo(1, r_port));
    println!("rendezvous up: {r_node}");

    // the peer: answers /ping and announces itself through the managed dht.
    let a_id = Identity::generate()?;
    let a_node = *a_id.node_id();
    let _a = Server::builder()
        .identity(a_id)
        .bind(lo(2, a_port))
        .on_request(|req, res| match req.path() {
            Some("/ping") => res.ok(b"pong"),
            _ => res.not_found(),
        })
        .dht([r_contact])
        .announce_as(lo(2, a_port))
        .serve()
        .await?;
    println!("peer announced: {a_node}");
    tokio::time::sleep(Duration::from_millis(800)).await;

    // the resolver: its runtime owns a dht, so resolve(node_id) is just .await.
    let resolver = Server::builder()
        .identity(Identity::generate()?)
        .bind(lo(3, g_port))
        .dht([r_contact])
        .serve()
        .await?;

    println!("resolving {a_node} by node_id alone...");
    let addr = resolver.resolve(&a_node, Duration::from_secs(8)).await?;

    let client = Client::builder()
        .identity(Identity::generate()?)
        .connect(&a_node, &addr)?;
    let resp = client.send(Method::Read, "/ping", &[])?;
    println!(
        "resolved + connected -> READ /ping = {} {:?}",
        resp.status().unwrap_or(Status::Error),
        String::from_utf8_lossy(resp.body())
    );

    let m = resolver.dht_metrics().await.unwrap();
    println!(
        "managed dht exchanged {} datagrams",
        m.datagrams_sent + m.datagrams_received
    );

    resolver.shutdown();
    Ok(())
}
