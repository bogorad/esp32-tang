#!/usr/bin/env bash
# Build and run the host tests. Usage: tests/run.sh [test-name-filter]
#
# Needs: cmake, a C++17 compiler, mbedTLS 3.x (CMake package), jose, clevis,
# curl. If a tool is missing and nix is available, this script re-runs itself
# inside `nix shell` with the tools. If a tool is still missing, it fails; it
# never skips tests.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
build_dir="${TANG_TEST_BUILD_DIR:-$root/build-tests}"

missing=()
for tool in cmake c++ jose clevis curl; do
  command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done

if [ "${#missing[@]}" -ne 0 ] && [ -z "${TANG_TEST_IN_NIX:-}" ] &&
   command -v nix >/dev/null 2>&1; then
  echo "run.sh: missing ${missing[*]}; re-running inside nix shell" >&2
  TANG_TEST_IN_NIX=1 exec nix shell --no-update-lock-file \
    nixpkgs#cmake nixpkgs#gnumake nixpkgs#gcc nixpkgs#jose nixpkgs#clevis \
    nixpkgs#curl nixpkgs#jq nixpkgs#mbedtls \
    -c bash "${BASH_SOURCE[0]}" "$@"
fi
if [ "${#missing[@]}" -ne 0 ]; then
  echo "run.sh: ERROR: missing tools: ${missing[*]}" >&2
  exit 1
fi

prefix="${MBEDTLS_PREFIX:-}"
if [ -z "$prefix" ]; then
  # Derive the mbedTLS prefix from a Nix store path on PATH, else from nix.
  prefix="$(nix build --no-link --print-out-paths --no-update-lock-file \
    nixpkgs#mbedtls 2>/dev/null | head -n 1)"
fi
if [ -z "$prefix" ] && [ -d /usr/include/mbedtls ]; then
  prefix=/usr
fi
if [ -z "$prefix" ]; then
  echo "run.sh: ERROR: set MBEDTLS_PREFIX to an mbedTLS 3.x install prefix" >&2
  exit 1
fi

# TANG_TEST_SANITIZE=address,undefined (or thread) builds with sanitizers; use a
# separate TANG_TEST_BUILD_DIR per sanitizer.
san_flags=""
if [ -n "${TANG_TEST_SANITIZE:-}" ]; then
  san_flags="-fsanitize=${TANG_TEST_SANITIZE} -fno-omit-frame-pointer -g"
fi

cmake -S "$root/tests" -B "$build_dir" -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="$san_flags" -DCMAKE_PREFIX_PATH="$prefix" >&2 || exit 1
cmake --build "$build_dir" -j "$(nproc 2>/dev/null || echo 2)" >&2 || exit 1
exec "$build_dir/tang_tests" "$@"
