// the managed dht. a server's runtime owns an attached dht, and resolve(node_id)
// is async. mirrors the nwdrop discover-by-node_id flow, but fully managed  -  no
// tick loop, no fd, no thread in the test. nodes bind fixed ports (so each knows
// its own announce address) on distinct loopback ips (so the three do not share
// one per-source-ip dht budget  -  the rate limit + token are keyed on ip).
#![cfg(feature = "runtime")]

use nwep::{Address, Bootstrap, Client, Identity, Method, Server, Status};
use std::time::Duration;

fn lo(octet: u8, port: u16) -> Address {
    Address::ipv4_mapped(127, 0, 0, octet, port)
}

#[tokio::test]
async fn managed_resolve_by_node_id() {
    // fixed ports so each node knows the address it announces (port 0 would be
    // un-announceable  -  peers must be able to dial it back).
    let (r_port, a_port, g_port) = (19401u16, 19402, 19403);

    // node R: the rendezvous. it lists itself as its sole bootstrap (a harmless
    // self-ping the dht drops as the local id), and just routes.
    let r_id = Identity::generate().unwrap();
    let r_node = *r_id.node_id();
    let r = Server::builder()
        .identity(r_id)
        .bind(lo(1, r_port))
        .dht([Bootstrap::new(&r_node, &lo(1, r_port))])
        .serve()
        .await
        .expect("rendezvous serves");
    let r_contact = Bootstrap::new(&r_node, &lo(1, r_port));

    // node A: answers /ping, and announces its address through the managed dht.
    let a_id = Identity::generate().unwrap();
    let a_node = *a_id.node_id();
    let a = Server::builder()
        .identity(a_id)
        .bind(lo(2, a_port))
        .on_request(|req, res| match req.path() {
            Some("/ping") => res.ok(b"pong"),
            _ => res.not_found(),
        })
        .dht([r_contact])
        .announce_as(lo(2, a_port))
        .serve()
        .await
        .expect("peer serves");

    // give A a moment to register its announce with R.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // the resolver: a managed server with its own dht. resolve A by node_id alone.
    let resolver = Server::builder()
        .identity(Identity::generate().unwrap())
        .bind(lo(3, g_port))
        .dht([r_contact])
        .serve()
        .await
        .expect("resolver serves");

    let addr = resolver
        .resolve(&a_node, Duration::from_secs(8))
        .await
        .expect("resolved A by node_id through the managed dht");

    // connect to the resolved address and exchange a request.
    let client = Client::builder()
        .identity(Identity::generate().unwrap())
        .connect(&a_node, &addr)
        .expect("connect to resolved address");
    let resp = client.send(Method::Read, "/ping", &[]).unwrap();
    assert_eq!(resp.status(), Some(Status::Ok));
    assert_eq!(resp.into_body(), b"pong");

    // the managed dht moved real traffic during the resolve.
    let m = resolver.dht_metrics().await.unwrap();
    assert!(
        m.datagrams_received > 0,
        "the managed dht exchanged datagrams"
    );

    a.shutdown();
    resolver.shutdown();
    r.shutdown();
}
