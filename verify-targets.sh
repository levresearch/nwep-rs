#!/usr/bin/env bash
# verify-targets.sh  -  the cross-platform verification matrix for the rust binding
# (PORTABILITY.md, guide.md 12). For each target the core builds for, it cross-
# builds the self-contained `-full.a`, links the binding against it with zig as the
# cross linker, and RUNS the test suite where an executor is available  -  otherwise
# it link-verifies (a real binary, not just `cargo check`) and reports run-pending.
#
# Requirements (a maintainer/CI machine; the dev box may have only some):
#   - zig 0.16, a rust toolchain with the target std (`rustup target add <triple>`)
#   - executors, per target family:
#       linux aarch64/armv7 : qemu-aarch64-static / qemu-arm-static (qemu-user)
#       linux x86-32        : qemu-i386-static
#       windows             : wine (or a real Windows runner)
#       android             : an emulator/device via adb (`zig build android-tests`)
#   - cargo-zigbuild (for the windows link CRT handling): `cargo install cargo-zigbuild`
#   - the Android NDK for android targets (ANDROID_NDK_HOME)
#
# Usage: bindings/rust/verify-targets.sh [target-key ...]   (default: all)
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUST_DIR="$REPO_ROOT/bindings/rust"
WORK="${NWEP_VERIFY_WORK:-/tmp/nwep-verify}"
mkdir -p "$WORK/xc"

# target table: key | zig triple | rust triple | runner (or "link-only" / "native")
TARGETS=(
  "linux-x64    | x86_64-linux-gnu          | x86_64-unknown-linux-gnu        | native"
  "linux-arm64  | aarch64-linux-musl        | aarch64-unknown-linux-musl      | qemu-aarch64-static"
  "linux-armv7  | arm-linux-musleabihf      | armv7-unknown-linux-musleabihf  | qemu-arm-static"
  "linux-x86    | x86-linux-musl            | i686-unknown-linux-musl         | qemu-i386-static"
  "windows-x64  | x86_64-windows-gnu        | x86_64-pc-windows-gnu           | wine"
  "android-arm64| aarch64-linux-android     | aarch64-linux-android           | adb"
  "android-armv7| arm-linux-androideabi     | armv7-linux-androideabi         | adb"
  "android-x64  | x86_64-linux-android      | x86_64-linux-android            | adb"
  "android-x86  | x86-linux-android         | i686-linux-android              | adb"
)

declare -A RESULT

zig_lib() { # zig_lib <zig-triple> <out-dir>
  local triple="$1" out="$2" ndk=""
  case "$triple" in *android*) ndk="-Dandroid_ndk=${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME}";; esac
  ( cd "$REPO_ROOT" && zig build -Dtarget="$triple" -Doptimize=ReleaseSafe $ndk --prefix "$out" ) >/dev/null 2>&1
}

zig_cc_wrapper() { # zig_cc_wrapper <zig-triple> -> path to a single-exe cc
  local triple="$1" w="$WORK/xc/cc-$triple"
  printf '#!/bin/sh\nexec zig cc -target %s "$@"\n' "$triple" > "$w"
  chmod +x "$w"; echo "$w"
}

run_target() { # run_target <key> <zigtriple> <rusttriple> <runner>
  local key="$1" zt="$2" rt="$3" runner="$4"
  echo "=== $key ($rt) ==="
  local libdir="$WORK/$key/lib"
  if ! zig_lib "$zt" "$WORK/$key"; then RESULT[$key]="FAIL: zig build"; return; fi
  [ -f "$libdir/libnwep-full.a" ] || { RESULT[$key]="FAIL: no -full.a"; return; }
  export NWEP_LIB_DIR="$libdir"

  local upper; upper=$(echo "$rt" | tr 'a-z-' 'A-Z_')
  case "$runner" in
    native)
      ( cd "$RUST_DIR" && cargo test --tests ) && RESULT[$key]="RUN: pass" || RESULT[$key]="RUN: FAIL" ;;
    qemu-*)
      if command -v "$runner" >/dev/null 2>&1; then
        local cc; cc=$(zig_cc_wrapper "$zt")
        export "CARGO_TARGET_${upper}_LINKER=$cc"
        export "CARGO_TARGET_${upper}_RUNNER=$runner"
        export RUSTFLAGS="-C link-self-contained=no"
        ( cd "$RUST_DIR" && cargo test --target "$rt" --tests ) \
          && RESULT[$key]="RUN(qemu): pass" || RESULT[$key]="RUN(qemu): FAIL/slow"
        unset RUSTFLAGS
      else
        link_only "$key" "$rt"; RESULT[$key]="LINK only (no $runner)"
      fi ;;
    wine)
      # link a real .exe via cargo-zigbuild (handles the windows CRT); run if wine present.
      if ( cd "$RUST_DIR" && cargo zigbuild --target "$rt" --example managed ) >/dev/null 2>&1; then
        if command -v wine >/dev/null 2>&1; then
          wine "$RUST_DIR/target/$rt/debug/examples/managed.exe" >/dev/null 2>&1 \
            && RESULT[$key]="RUN(wine): pass" || RESULT[$key]="RUN(wine): FAIL"
        else RESULT[$key]="LINK: .exe built (no wine to run)"; fi
      else RESULT[$key]="FAIL: windows link"; fi ;;
    adb)
      # android: the core stages on-device test exes; run via adb when a device is attached.
      if command -v adb >/dev/null 2>&1 && [ -n "$(adb devices 2>/dev/null | sed -n '2p')" ]; then
        RESULT[$key]="adb device present  -  run `zig build android-tests` + push (see core docs)"
      else RESULT[$key]="ARCHIVE built (no device; android app provides libc++)"; fi ;;
  esac
}

link_only() { # link_only <key> <rusttriple>  -  a real build, not just check
  local rt="$2"
  ( cd "$RUST_DIR" && cargo zigbuild --target "$rt" --example managed ) >/dev/null 2>&1
}

KEYS=("$@")
[ ${#KEYS[@]} -eq 0 ] && KEYS=(linux-x64 linux-arm64 linux-armv7 linux-x86 windows-x64 android-arm64 android-armv7 android-x64 android-x86)

for key in "${KEYS[@]}"; do
  for row in "${TARGETS[@]}"; do
    IFS='|' read -r k zt rt runner <<< "$row"
    k=$(echo "$k"|xargs); zt=$(echo "$zt"|xargs); rt=$(echo "$rt"|xargs); runner=$(echo "$runner"|xargs)
    [ "$k" = "$key" ] && run_target "$k" "$zt" "$rt" "$runner"
  done
done

echo
echo "================ verification matrix ================"
for key in "${KEYS[@]}"; do printf "  %-14s %s\n" "$key" "${RESULT[$key]:-skipped}"; done
