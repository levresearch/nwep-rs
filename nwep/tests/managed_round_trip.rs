// the managed (L2) round trip, fully async end to end. both sides run on their
// own owner threads behind the actor bridge NWG0600, and the test never
// touches a tick loop or a raw fd. proves Server::serve().await and
// AsyncClient::send().await talk over the real c transport.
#![cfg(feature = "runtime")]

use nwep::{Address, Client, Identity, Method, Server, Status};

#[tokio::test]
async fn managed_server_and_client_round_trip() {
    let server = Server::builder()
        .identity(Identity::generate().unwrap())
        .bind(Address::loopback(0))
        .on_request(|req, res| match req.path() {
            Some("/hello") => res.ok(b"hi there"),
            _ => res.not_found(),
        })
        .serve()
        .await
        .expect("serve");

    let client = Client::builder()
        .identity(Identity::generate().unwrap())
        .connect_async(&server.node_id(), &Address::loopback(server.local_port()))
        .await
        .expect("connect");

    let hello = client
        .send(Method::Read, "/hello", &[])
        .await
        .expect("send /hello");
    assert_eq!(hello.status(), Some(Status::Ok));
    assert_eq!(hello.into_body(), b"hi there");

    let missing = client
        .send(Method::Read, "/nope", &[])
        .await
        .expect("send /nope");
    assert_eq!(missing.status(), Some(Status::NotFound));

    // two more requests prove the connection is reused in order.
    for _ in 0..2 {
        let r = client.send(Method::Read, "/hello", &[]).await.unwrap();
        assert_eq!(r.into_body(), b"hi there");
    }

    server.shutdown();
}
