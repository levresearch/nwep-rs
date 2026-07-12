// nwep build script. nwep-sys resolves and re-exports the shared library
// directory through its links metadata as DEP_NWEP_LIB_DIR. fold the same rpath
// into this crate's tests and examples so they find the library at runtime.

fn main() {
    if let Ok(dir) = std::env::var("DEP_NWEP_LIB_DIR") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
