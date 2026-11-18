#!/usr/bin/env bash
# Config-validation tests for components/tang_server/__init__.py using
# `esphome config` (no firmware build). Usage: tests/esphome_config.sh
# Re-runs itself inside `nix shell nixpkgs#esphome` when esphome is missing.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1

if ! command -v esphome >/dev/null 2>&1; then
  if [ -z "${TANG_TEST_IN_NIX:-}" ] && command -v nix >/dev/null 2>&1; then
    TANG_TEST_IN_NIX=1 exec nix shell --no-update-lock-file nixpkgs#esphome \
      -c bash "${BASH_SOURCE[0]}" "$@"
  fi
  echo "esphome_config.sh: ERROR: esphome not found" >&2
  exit 1
fi

work="$(mktemp -d)" || exit 1
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT TERM HUP

good_seed=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
other_seed=a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
pass=0
fail=0

cat > "$work/secrets.yaml" <<SECRETS
wifi_ssid: "test"
wifi_password: "testtesttest"
SECRETS

# case <name> <expect: ok|fail> <expected-message-fragment> <tang_server yaml body>
case_run() {
  local name="$1" expect="$2" fragment="$3" body="$4"
  local dir="$work/$name"
  mkdir -p "$dir" || return 1
  cp "$work/secrets.yaml" "$dir/secrets.yaml"
  cat > "$dir/c.yaml" <<YAML
esphome:
  name: t
esp32:
  board: esp32dev
  framework:
    type: esp-idf
wifi:
  ssid: !secret wifi_ssid
  password: !secret wifi_password
web_server:
external_components:
  - source:
      type: local
      path: $root/components
    components: [tang_server]
tang_server:
$body
YAML
  local out status
  out="$(cd "$dir" && esphome config c.yaml 2>&1)"
  status=$?
  local ok=1
  if [ "$expect" = ok ] && [ "$status" -ne 0 ]; then ok=0; fi
  if [ "$expect" = fail ] && [ "$status" -eq 0 ]; then ok=0; fi
  if [ "$expect" = fail ] && ! grep -qF -- "$fragment" <<<"$out"; then ok=0; fi
  if [ "$ok" -eq 1 ]; then
    echo "[  OK  ] $name"
    pass=$((pass + 1))
  else
    echo "[ FAIL ] $name (expected $expect, status $status, fragment '$fragment')"
    echo "$out" | tail -15
    fail=$((fail + 1))
  fi
}

case_run unattended_ok ok "" "  unattended: true
  seed: \"$good_seed\""
case_run unattended_old_seeds_ok ok "" "  unattended: true
  seed: \"$good_seed\"
  old_seeds:
    - \"$other_seed\""
case_run password_ok_60d ok "" "  initial_password: \"correct horse\"
  key_lifetime: 60d
  reset_token: 3"
case_run unattended_needs_seed fail "'seed' is required" "  unattended: true"
case_run seed_too_short fail "only 31 bytes" "  unattended: true
  seed: \"${good_seed:0:62}\""
case_run seed_odd_length fail "even number of hex digits" "  unattended: true
  seed: \"${good_seed:0:63}\""
case_run seed_not_hex fail "must be hexadecimal" "  unattended: true
  seed: \"${good_seed:0:60}zzzz\""
case_run seed_degenerate fail "degenerate" "  unattended: true
  seed: \"0000000000000000000000000000000000000000000000000000000000000000\""
case_run unattended_rejects_password fail "'initial_password' is not used" "  unattended: true
  seed: \"$good_seed\"
  initial_password: \"x\""
case_run unattended_rejects_lifetime fail "'key_lifetime' is not used" "  unattended: true
  seed: \"$good_seed\"
  key_lifetime: 1h"
case_run password_needs_password fail "'initial_password' is required" "  unattended: false"
case_run seed_needs_unattended fail "needs 'unattended: true'" "  initial_password: \"pw\"
  seed: \"$good_seed\""
case_run old_seeds_needs_unattended fail "needs 'unattended: true'" "  initial_password: \"pw\"
  old_seeds:
    - \"$other_seed\""
case_run old_seed_equals_current fail "duplicate or the current seed" "  unattended: true
  seed: \"$good_seed\"
  old_seeds:
    - \"$good_seed\""
case_run old_seed_duplicates fail "duplicate or the current seed" "  unattended: true
  seed: \"$good_seed\"
  old_seeds:
    - \"$other_seed\"
    - \"$other_seed\""

echo "$((pass + fail)) config cases, $fail failed"
[ "$fail" -eq 0 ]
