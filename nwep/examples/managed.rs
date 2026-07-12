// the managed (L2) happy path, the five minute quickstart. a fully async server
// and client, no tick loop, no fd, no thread in sight. the runtime owns the
// loops behind the actor bridge NWG0600. requires the default `runtime` feature.

use nwep::{Address, Client, Identity, Method, Server, Status};

#[tokio::main]
async fn main() -> nwep::Result<()> {
    // a server that answers read /hello, running on its own owned loop.
    let server = Server::builder()
        .identity(Identity::generate()?)
        .bind(Address::loopback(0))
        .on_request(|req, res| match req.path() {
            Some("/hello") => res.ok(b"hi from the managed runtime\n"),
            _ => res.not_found(),
        })
        .serve()
        .await?;
    println!(
        "serving node {} on [::1]:{}",
        server.node_id(),
        server.local_port()
    );

    // a client that dials it and sends, all async.
    let client = Client::builder()
        .identity(Identity::generate()?)
        .connect_async(&server.node_id(), &Address::loopback(server.local_port()))
        .await?;

    let resp = client.send(Method::Read, "/hello", &[]).await?;
    println!("status {}", resp.status().unwrap_or(Status::Error));
    println!("body   {}", String::from_utf8_lossy(resp.body()).trim_end());

    server.shutdown();
    Ok(())
}
