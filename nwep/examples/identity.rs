// the smallest real program against the binding. generates an identity, prints
// its node_id, and proves the base58 name round trips and the key binding holds.
// mirrors the discover-by-nodeid proof the sandbox apps rest on.

use nwep::{Identity, NodeId};

fn main() -> nwep::Result<()> {
    println!("nwep library version {}", nwep::version());

    let id = Identity::generate()?;
    let name = id.node_id().to_base58();
    println!("generated node {name}");

    // the printed name decodes back to the very same identity.
    let parsed: NodeId = name.parse()?;
    assert_eq!(&parsed, id.node_id());

    // and the node_id is genuinely the binding of this identity's public key.
    assert!(id.node_id().verify(id.public_key()));

    println!("ok, node_id round trips and verifies against its public key");
    Ok(())
}
