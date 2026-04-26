#!/usr/bin/env bash

URL="${1:-${TANG_URL:-http://esphome.lan}}"
PASSWORD="${2:-${TANG_INITIAL_PASSWORD:-}}"
PLAINTEXT="${3:-probe-secret}"

TMP_DIR="$(mktemp -d)"
if [ "$?" -ne 0 ]; then
  printf 'error: failed to create temp directory\n' >&2
  exit 1
fi

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1
  if [ "$?" -ne 0 ]; then
    fail "missing required command: $1"
  fi
}

if [ -z "$PASSWORD" ]; then
  fail "usage: $0 <url> <tang-initial-password> [plaintext]"
fi

need curl
need jose
need clevis

PUB_JWK="$TMP_DIR/pub.jwk"
ACTIVATE_JWE="$TMP_DIR/activate.jwe"
ACTIVATE_BODY="$TMP_DIR/activate.body"
ADV_BODY="$TMP_DIR/adv.body"
CLEVIS_JWE="$TMP_DIR/clevis.jwe"
CLEVIS_PLAIN="$TMP_DIR/clevis.plain"

printf 'Fetching admin public key from %s/pub\n' "$URL"
curl --connect-timeout 5 --max-time 15 -fsS "$URL/pub" >"$PUB_JWK"
if [ "$?" -ne 0 ]; then
  fail "failed to fetch $URL/pub"
fi

printf 'Activating Tang server\n'
printf '%s' "$PASSWORD" | jose jwe enc -I- -k "$PUB_JWK" -o "$ACTIVATE_JWE" -i '{"protected":{"enc":"A128GCM"}}'
if [ "$?" -ne 0 ]; then
  fail "failed to create activation JWE"
fi

ACTIVATE_STATUS="$(curl --connect-timeout 5 --max-time 15 -sS -X POST \
  -H 'Content-Type: application/json' \
  --data-binary @"$ACTIVATE_JWE" \
  -w '%{http_code}' \
  -o "$ACTIVATE_BODY" \
  "$URL/activate")"
if [ "$?" -ne 0 ]; then
  fail "failed to POST $URL/activate"
fi

if [ "$ACTIVATE_STATUS" != "200" ] && ! grep -q '^Already active$' "$ACTIVATE_BODY"; then
  printf 'activate status: %s\n' "$ACTIVATE_STATUS" >&2
  printf 'activate body: %s\n' "$(cat "$ACTIVATE_BODY")" >&2
  fail "activation failed"
fi
printf 'Activation response: %s\n' "$(cat "$ACTIVATE_BODY")"

printf 'Fetching Tang advertisement from %s/adv/\n' "$URL"
ADV_STATUS="$(curl --connect-timeout 5 --max-time 15 -sS --path-as-is \
  -w '%{http_code}' \
  -o "$ADV_BODY" \
  "$URL/adv/")"
if [ "$?" -ne 0 ]; then
  fail "failed to fetch $URL/adv/"
fi
if [ "$ADV_STATUS" != "200" ]; then
  printf 'adv status: %s\n' "$ADV_STATUS" >&2
  printf 'adv body: %s\n' "$(cat "$ADV_BODY")" >&2
  fail "advertisement fetch failed"
fi
printf 'Advertisement bytes: %s\n' "$(wc -c <"$ADV_BODY")"

printf 'Running Clevis bind/recover round trip\n'
printf '%s' "$PLAINTEXT" | clevis encrypt tang "{\"url\":\"$URL\"}" -y >"$CLEVIS_JWE"
if [ "$?" -ne 0 ]; then
  fail "clevis encrypt failed"
fi

clevis decrypt <"$CLEVIS_JWE" >"$CLEVIS_PLAIN"
if [ "$?" -ne 0 ]; then
  fail "clevis decrypt failed"
fi

if ! cmp -s "$CLEVIS_PLAIN" <(printf '%s' "$PLAINTEXT"); then
  printf 'expected: %s\n' "$PLAINTEXT" >&2
  printf 'actual: %s\n' "$(cat "$CLEVIS_PLAIN")" >&2
  fail "clevis round trip plaintext mismatch"
fi

printf 'Clevis round trip OK: %s\n' "$(cat "$CLEVIS_PLAIN")"
