// nwep-sys build script. statically links the self-contained nwep archive
// (libnwep-full.a with the trust feature, else libnwep_core-full.a) - one archive
// that already bundles the c deps (BoringSSL, ngtcp2, zstd, +blst) and zig's
// libc++/libc++abi, so the binding produces a self-contained binary with no
// runtime .so to ship NWG1200.
//
// resolution order, first match wins
//  1. NWEP_LIB_DIR - explicit override; on Windows the installer sets this.
//  2. repo_root/zig-out/lib - a monorepo checkout's own build; runs zig build
//     there if it's missing but the directory looks like the nwep repo.
//  3. pkg-config (Linux only) - the installer writes nwep.pc / nwep_core.pc;
//     also covers user installs when PKG_CONFIG_PATH includes ~/.local/lib/pkgconfig.
//  4. the nwep-installer's default install locations for this OS (user, then
//     system) - fallback for Windows where there is no pkg-config.
// failing all four, panics with every path actually checked and install
// instructions, rather than a bare linker error, so it is clear what to fix.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("../../..");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    let base = if std::env::var("CARGO_FEATURE_TRUST").is_ok() {
        "nwep"
    } else {
        "nwep_core"
    };
    let archive_name = format!("lib{base}-full.a");

    let mut checked: Vec<String> = Vec::new();
    let lib_dir = resolve_lib_dir(&repo_root, base, &archive_name, &target_os, &mut checked);

    let lib_dir = match lib_dir {
        Some(dir) => dir,
        None => {
            let hint = if target_os == "windows" {
                "Install nwep with the GUI installer (http://pkg.rebuildtheinter.net/tools/latest/)\n\
                 - it sets NWEP_LIB_DIR automatically.\n\
                 Or set NWEP_LIB_DIR manually to the directory containing the .a files."
            } else {
                "Install nwep with the GUI installer (http://pkg.rebuildtheinter.net/tools/latest/),\n\
                 or set PKG_CONFIG_PATH to ~/.local/lib/pkgconfig if you used a user-scope install.\n\
                 You can also set NWEP_LIB_DIR or run `zig build` in the repo root."
            };
            panic!(
                "nwep-sys: could not find {archive_name}. Checked:\n  - {}\n\n{hint}",
                checked.join("\n  - "),
            )
        }
    };

    println!("cargo:lib_dir={}", lib_dir.display());
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static={base}-full");

    for lib in system_libs(&target_os) {
        println!("cargo:rustc-link-lib={lib}");
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=NWEP_LIB_DIR");
    println!(
        "cargo:rerun-if-changed={}",
        lib_dir.join(&archive_name).display()
    );
}

/// Walks the resolution order described at the top of this file, returning the
/// directory that holds archive_name on the first match. checked collects a
/// human-readable trail of everywhere this looked, for the panic message.
fn resolve_lib_dir(
    repo_root: &Path,
    base: &str,
    archive_name: &str,
    target_os: &str,
    checked: &mut Vec<String>,
) -> Option<PathBuf> {
    // 1. explicit override.
    if let Ok(dir) = std::env::var("NWEP_LIB_DIR") {
        let dir = PathBuf::from(dir);
        checked.push(format!("{} (NWEP_LIB_DIR)", dir.display()));
        if dir.join(archive_name).exists() {
            return Some(dir);
        }
    }

    // 2. the monorepo's own zig-out, auto-building it if this looks like the
    // nwep repo itself (build.zig present) and zig is on PATH.
    if let Ok(repo_root) = repo_root.canonicalize() {
        let zig_out_lib = repo_root.join("zig-out/lib");
        checked.push(format!("{} (zig-out)", zig_out_lib.display()));
        if zig_out_lib.join(archive_name).exists() {
            return Some(zig_out_lib);
        }
        if repo_root.join("build.zig").exists() {
            eprintln!(
                "nwep-sys: {} not found, trying `zig build` in {}",
                zig_out_lib.join(archive_name).display(),
                repo_root.display()
            );
            let built = Command::new("zig")
                .arg("build")
                .current_dir(&repo_root)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if built && zig_out_lib.join(archive_name).exists() {
                return Some(zig_out_lib);
            }
        }
    }

    // 3. pkg-config - Linux only; the installer writes nwep.pc / nwep_core.pc.
    //    also covers user installs when PKG_CONFIG_PATH=~/.local/lib/pkgconfig is set.
    if target_os == "linux" {
        let pc_name = if base == "nwep" { "nwep" } else { "nwep_core" };
        if let Ok(lib) = pkg_config::Config::new()
            .cargo_metadata(false)
            .probe(pc_name)
        {
            if let Some(dir) = lib.link_paths.into_iter().next() {
                checked.push(format!("{} (pkg-config)", dir.display()));
                if dir.join(archive_name).exists() {
                    return Some(dir);
                }
            }
        }
        checked.push(format!(
            "pkg-config {pc_name} (not found or archive missing)"
        ));
    }

    // 4. the GUI installer's default locations for this OS, user then system.
    for dir in installer_default_lib_dirs(target_os) {
        checked.push(format!("{} (installer default)", dir.display()));
        if dir.join(archive_name).exists() {
            return Some(dir);
        }
    }

    None
}

/// the nwep-installer's default install lib dirs for an OS, user scope first,
/// then system scope. Mirrors installer/src-tauri/src/target.rs::default_prefix
/// / locations_at exactly - keep these in sync if that file changes.
fn installer_default_lib_dirs(target_os: &str) -> Vec<PathBuf> {
    match target_os {
        "linux" => {
            let mut dirs = Vec::new();
            if let Some(home) = dirs::home_dir() {
                dirs.push(home.join(".local/lib"));
            }
            dirs.push(PathBuf::from("/usr/local/lib"));
            dirs
        }
        "windows" => {
            let mut dirs = Vec::new();
            if let Some(local_data) = dirs::data_local_dir() {
                dirs.push(local_data.join("Programs/nwep/lib"));
            }
            let program_files =
                std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
            dirs.push(PathBuf::from(program_files).join("nwep/lib"));
            dirs
        }
        _ => Vec::new(),
    }
}

fn system_libs(target_os: &str) -> &'static [&'static str] {
    match target_os {
        "linux" => &["m", "dl", "pthread"],
        "android" => &["m", "dl", "log"],
        "windows" => &[
            "ws2_32", "bcrypt", "crypt32", "secur32", "advapi32", "userenv", "ntdll",
        ],
        "macos" | "ios" => &["framework=Security", "framework=CoreFoundation"],
        _ => &[],
    }
}
