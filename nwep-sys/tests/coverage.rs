// coverage anchor for the sys layer NWG1000.
//
// symbols.txt is the authoritative export set of libnwep_core + libnwep, checked
// in and regenerated from the built .so files (see the header of symbols.txt).
// this test diffs the extern fns declared in src/lib.rs against it.
//
// it hard fails on a phantom, a declared extern that is not a real export, since
// that is a typo or a symbol removed from the header and would be a link error
// or undefined behavior. it reports forward progress as a count, because the sys
// layer is filled in slice by slice. when every symbol is declared the equality
// assert at the bottom turns the count into a totality guarantee.

use std::collections::BTreeSet;

fn authoritative() -> BTreeSet<String> {
    include_str!("../symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

fn declared() -> BTreeSet<String> {
    // scan the ffi source for `fn nwep_...(` extern declarations. doc lines that
    // merely mention a symbol read `nwep_x does ...`, never `fn nwep_x`, so this
    // matches declarations only.
    let src = include_str!("../src/lib.rs");
    let mut out = BTreeSet::new();
    for (_, after) in src
        .match_indices("fn nwep_")
        .map(|(i, _)| (i, &src[i + 3..]))
    {
        let name = "nwep_".to_string()
            + after["nwep_".len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<String>()
                .as_str();
        out.insert(name);
    }
    out
}

#[test]
fn no_phantom_externs() {
    let auth = authoritative();
    let decl = declared();
    let phantoms: Vec<_> = decl.difference(&auth).collect();
    assert!(
        phantoms.is_empty(),
        "sys declares {phantoms:?} which are not exported by the library \
         (typo, or removed from the header). fix the declaration or symbols.txt."
    );
    eprintln!(
        "nwep-sys coverage: {} / {} symbols declared",
        decl.len(),
        auth.len()
    );
}

// the sys layer is complete. every exported symbol is declared. this now runs
// by default to lock in totality NWG1000 D1  -  adding a c export without its
// sys declaration fails ci here.
#[test]
fn all_symbols_declared() {
    let missing: Vec<_> = authoritative().difference(&declared()).cloned().collect();
    assert!(
        missing.is_empty(),
        "sys is missing {} symbols: {missing:?}",
        missing.len()
    );
}
