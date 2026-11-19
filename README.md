# ESP32 Tang Server

Tang server (Clevis network unlock for LUKS) for ESP32. Two build surfaces
share one Tang core in `components/tang_server/` (also linked from `src/`):

- ESPHome external component `tang_server` (the maintained path).
- Standalone ESP-IDF/Arduino firmware in `main/` and `standalone/`
  (password mode only; not compiled in this change, see Status).

## What's new (2026-11-19)

- **`signing_thumbprint` text sensor** (diagnostic): the SHA-256 thumbprint of
  the signing key, for Clevis bindings. Works in both modes.
- **Tang endpoints bypass `web_server` auth** (ESPHome 2026.3.0 or later), so
  Clevis can unlock when `web_server: auth:` is set. See
  [Authentication and `web_server`](#authentication-and-web_server).
- **mbedTLS 2.x build fix** (for LibreTiny, rtl87xx): the crypto code builds
  with mbedTLS 2.x and 3.x, and the host tests pass on both. rtl87xx is still
  not supported: the firmware build stops at `std::mutex`, which the
  LibreTiny ARM toolchain does not provide.

## What's new (2026-11-18)

- **Unattended mode** with seed-derived keys (HKDF-SHA256): options `seed` and
  `old_seeds`. The server is active at boot, with no activation and no flash
  writes.
- **SHA-1 and SHA-256 key IDs** on `/adv/<thp>` and `/rec/<kid>`. Clevis 17 and
  later use SHA-256.
- **Request path normalization**: Clevis URLs with a trailing slash and
  `//adv` now work.
- **POST body handling for ESPHome 2026.8 and later** (`handleBody`). Older
  versions use the socket-read fallback.
- **Password-mode hardening**: no `GET /deactivate`, password check before
  any change, PBKDF2 with a random salt, back-off on wrong passwords, a
  versioned record, no silent re-init of a bad record, and `reset_token`.
- **Thread safety**: one mutex in the core; ESPHome events go through a queue.
- **Host test suite** with real Clevis round trips: `make test`.
- **Example and secrets hygiene**: `secrets.sample.yaml`, no committed secrets.

New to Tang and Clevis, or setting up a device? Read the
[guide](docs/guide.md): how network-bound unlock works, which mode to pick,
ESPHome setup step by step, Clevis `sss` binding, LUKS2 header size, NixOS and
troubleshooting.

## Status

Experimental. Verified on a host (see Tests): the core against mbedTLS 3.x,
`jose`, and a real Clevis encrypt/decrypt round trip. Verified on hardware:
ESP32-C6 (M5Stack NanoC6) and classic ESP32 (M5Stack Atom), ESPHome 2026.9.1,
ESP-IDF framework. On the C6 with Bluetooth proxy and web server the app used
about 87% of a 1.75 MB app partition. The standalone firmware was not rebuilt
for this release. Do a live Clevis test on your device before you rely on it.

## Two modes

| | Password mode (default) | Unattended mode |
|---|---|---|
| Keys | random, stored in flash | derived from `seed` at every boot |
| After boot | needs `POST /activate` | active at once |
| Expiry | `key_lifetime` (default 1 h) | none |
| Flash writes | key record, reset token | none |
| `/pub`, `/activate`, `/deactivate` | work | `404` |
| Power outage recovery | needs a person or a script | works with nobody present |

## Unattended mode (for unattended LUKS unlock)

```yaml
tang_server:
  id: tang_component
  unattended: true
  seed: !secret tang_seed       # openssl rand -hex 32 ; one per device
  # old_seeds:                  # rotation only, see below
  #   - !secret tang_old_seed
```

`seed` is required, hex, at least 64 hex characters (32 bytes), at most 256.
The build fails otherwise. Degenerate seeds (fewer than 8 distinct bytes) are
refused too. Put it in `secrets.yaml` as a quoted string.

Also set `reboot_timeout: 0s` for `api:` and `wifi:` (see
`esphome-tang/esp32tang-unattended.yaml`). The ESPHome default reboots the
device after 15 minutes without a Home Assistant connection. A Tang server must
keep serving without Home Assistant.

### How the keys are made

- IKM = the decoded seed bytes. HKDF-SHA256, salt = the ASCII string
  `esp32-tang/v1`.
- Signing key and exchange key use distinct `info` strings:
  `esp32-tang/v1/signing` and `esp32-tang/v1/exchange`, each followed by a
  zero byte and a one-byte counter.
- The 32-byte output must be in [1, n-1] for P-256. If not, the counter
  increases and HKDF runs again (rejection sampling; no modulo bias).
- The same seed gives the same keys on every boot and every build. The
  derivation is pinned by a known-answer test, cross-checked with an
  independent Go program (`tests/ref/derive.go`). Never change it for an
  existing deployment.

### Threat model (read this)

- **The seed is in the firmware image.** Anyone who gets one ESP32's flash, or
  the firmware binary or the build directory, has the Tang keys. With the keys
  and the encrypted disk they can unlock it. Without the seed the device is
  just a normal Tang server.
- Anyone who can reach the device on the network can use it as a Tang server.
  That is the Tang model: it is safe against someone who only sees the traffic,
  not against someone who can both reach a server and read the disk.
- Enable **ESP32 flash encryption and secure boot** for any device that is not
  physically controlled. The seed in `secrets.yaml` and in ESPHome's build
  directory is plain text on the build host.
- Use **one different seed per device**, and keep an offline backup of each
  seed. Do not reuse the seed of a lost or stolen device.
- With Clevis `sss` and `t=1` of 3 servers, **any one** server (or its seed) is
  enough to unlock. This gives availability, not extra security. Use `t=2` of 3
  if one stolen device must not be enough.
- Reflashing with the same seed keeps the server identity, so existing Clevis
  bindings keep working. A new seed is a new identity: every disk bound to it
  must be re-bound.
- Plain HTTP carries the Tang exchange. That is normal for Tang, but keep the
  servers on a network you trust against an active attacker.

### Rotation (`old_seeds`)

`old_seeds` follows tangd's hidden rotated keys:

- The exchange keys of old seeds stay valid for `POST /rec/<kid>`, so existing
  bindings still unlock.
- They are not advertised: `/adv` lists only the current signing and exchange
  keys.
- The old signing keys may co-sign `GET /adv/<thp>` when `<thp>` is the
  thumbprint of that old signing key. The reply is then a general JWS with two
  signatures (current key and old key), like tangd. `GET /adv` is signed by the
  current key only.

Steps: set the new `seed`, move the old one to `old_seeds`, flash, re-bind
every disk (`clevis luks regen` / bind again) to the new key, then remove the
old seed on the next flash.

### Key IDs

`/rec/<kid>` and `/adv/<thp>` accept the RFC 7638 thumbprint of the key as
base64url without padding, as **SHA-256 or SHA-1**, like tangd. Clevis 17 and
later send SHA-256.

## Password mode

```yaml
tang_server:
  id: tang_component
  initial_password: !secret tang_initial_password   # 1 to 128 bytes
  key_lifetime: 1h          # 64-bit; values above 49 days work
  reset_token: 0            # see below
```

- On first boot the component creates an admin (signing) key and a Tang
  exchange key. The exchange key is encrypted with a key from
  `initial_password` using **PBKDF2-HMAC-SHA256, random 16-byte salt, 20000
  iterations** (about 0.3 to 1 s on an ESP32; an estimate, not measured on
  hardware). Both are stored in ESPHome preferences in a versioned record
  (magic, version, length, SHA-256 checksum).
- Flash is not encrypted by ESPHome preferences. Enable flash encryption if
  flash extraction is in your threat model.
- The key is held in RAM after `POST /activate` and erased after
  `key_lifetime` or `POST /deactivate`. Expiry uses a 64-bit monotonic clock.
- `POST /deactivate` needs the current password. It only erases the key from
  RAM. It does not change the stored record. A wrong password returns 401.
  `GET /deactivate` does not exist (405).
- Wrong passwords on `/activate` and `/deactivate` back off: 1 s after the
  first failure, doubling, at most 5 min (`429`). The counter lives in RAM.
- A stored record that fails validation (corrupt, other format, older
  firmware) is never replaced. The server logs an error, stays inactive and
  answers `503`. To start over, change `reset_token` (and keep
  `initial_password` set). The record is wiped once when the configured token
  differs from the stored one. Remove nothing afterwards: keep the new number.
  If the token slot was lost too, erase the flash.
- Records from older firmware (single unsalted SHA-256 key derivation) do not
  decode and are never misread.
- **Replay limit.** The activation JWE is encrypted to the admin key but has
  no nonce or timestamp. Someone who captured it can replay it while the server
  is inactive and re-activate it. They do not learn any key. A challenge
  endpoint would fix this but would change the protocol for existing scripts,
  so it is not done. Keep the management network trusted, or use unattended
  mode.

Example activation flow:

```bash
curl http://<esp-ip>/pub > server_pub.jwk
echo -n "change-me" | jose jwe enc -I- -k server_pub.jwk -o request.jwe -i '{"protected":{"enc":"A128GCM"}}'
curl -X POST -H "Content-Type: application/json" -d @request.jwe http://<esp-ip>/activate
curl http://<esp-ip>/adv
```

## HTTP endpoints

| Endpoint | Password mode | Unattended |
|---|---|---|
| `GET /adv`, `GET /adv/<thp>` | 403 while inactive | signed advertisement |
| `POST /rec/<kid>` | 403 while inactive | recovery |
| `GET /pub` | admin public key JWK | 404 |
| `POST /activate` | activate (JWE body) | 404 |
| `POST /deactivate` | deactivate (JWE body, password proof) | 404 |

Request bodies are capped at 4096 bytes. POST requests must send
`Content-Type: application/json` or `application/jwk+json` (Clevis and the demo
script do). On ESP-IDF, current ESPHome (read in the 2026.10.2 source) delivers
such bodies to `handleBody()` with the same request pointer and chunk index
starting at 0; the component buffers them there. ESPHome consumes
`application/x-www-form-urlencoded` bodies itself (for example plain
`curl -d`), so those get a clear 400. For older ESPHome versions that never call
`handleBody()` (checked: 2026.5.1) the component reads the body from the
socket.

### Authentication and `web_server`

The Tang endpoints bypass `web_server` authentication on purpose. Clevis and
other Tang clients send plain `GET /adv` and `POST /rec/<kid>` requests. They
cannot send HTTP Basic or Digest credentials, so with `web_server: auth:` set
on the same server every unlock would fail with `401`. The component registers
its handler with `add_handler_without_auth()` for this reason. That method
exists since ESPHome 2026.3.0 (checked in the 2026.3.0, 2026.5.1, 2026.9.1
and 2026.10.2 sources). On older ESPHome the component falls back to
`add_handler()`, logs a warning, and `web_server` auth then also covers the
Tang paths. Use ESPHome 2026.3.0 or later with `web_server` auth.

`web_server` auth still protects the other ESPHome web pages. It does not
protect these paths:

- `/adv` and `/rec`: open on purpose, as in `tangd`. They give out the
  public advertisement and the recovery exchange. The recovery reply is only
  useful to a client that holds the matching Clevis binding.
- `/pub`, `/activate`, `/deactivate` (password mode): the admin endpoints.
  They are open at the HTTP layer; the password proof in the JWE body is the
  access control, with back-off on wrong passwords.
- In unattended mode the admin endpoints do not exist: they answer `404`.

So restrict who can reach the device at the network level (VLAN, firewall).

## ESPHome notes

- Examples: `esphome-tang/esp32tang.yaml` (password mode),
  `esphome-tang/esp32tang-unattended.yaml`, and local-component variants
  `tang_server.yaml` and `tang_server_unattended.yaml`.
- Copy `esphome-tang/secrets.sample.yaml` to `esphome-tang/secrets.yaml` and
  replace every value. `secrets.yaml` is git-ignored.
- Sensors and automations (`on_request`, `on_activate`, ...) run on the ESPHome
  main loop. The HTTP task only queues events (bounded queue, oldest dropped
  with a warning).
- Triggers: `on_request(path, method, status)`, `on_activate(success)`,
  `on_deactivate()`, `on_recovery(success)`. Entities: `binary_sensor: active`;
  `sensor: request_count, activation_count, recovery_count, last_status`;
  `text_sensor: last_path, last_method, last_error, signing_thumbprint`.
- `signing_thumbprint` (diagnostic category) is the RFC 7638 SHA-256 thumbprint
  of the signing key that `/adv` advertises, base64url without padding. It
  is the value to pass as `thp` in a Clevis binding (`clevis encrypt tang`
  `'{"url":"...","thp":"<value>"}'`). It is published from the main loop.
  It is set at boot in both modes: the key exists from boot in unattended mode,
  and password mode creates or loads the admin key during setup.
- If the core cannot start, the component logs an error, sets a component
  error status and every Tang request answers `503`.

Compile the examples with throwaway secrets:

```bash
docker compose -f esphome-tang/docker-compose.yml run --rm esphome   # password mode
```

or with Nix: `WORK_ROOT=$PWD nix shell nixpkgs#esphome -c bash esphome-tang/esphome-compile.sh tang_server_unattended.yaml`.

## Tests

```bash
make test           # host tests: core, crypto vectors, jose, real Clevis round trip
make test-esphome   # ESPHome config validation (seed rules, mode rules)
```

Sanitizers: `TANG_TEST_SANITIZE=address,undefined TANG_TEST_BUILD_DIR=build-asan make test`.
More in the [guide](docs/guide.md).

`make test` runs `tests/run.sh`. It needs cmake, a C++17 compiler, mbedTLS 3.x,
`jose`, `clevis` and `curl`. If a tool is missing and `nix` exists, the script
re-runs itself in `nix shell`. It never skips: a missing tool is an error. Set
`MBEDTLS_PREFIX` to use a non-Nix mbedTLS. `ctest` also works in
`build-tests/` after a run.

What is covered: seed derivation (deterministic, distinct, pinned known
answers), HKDF and PBKDF2 vectors, SHA-1 and SHA-256 thumbprints against
`jose jwk thp`, `/adv` JWS verified by `jose jws ver`, ECMR recovery against an
independent `jose jwk exc`, invalid client points, deactivate with a wrong
password, corrupt and foreign records, reset token, body buffer reset, and
Clevis encrypt/decrypt through `tests/tang_shim.cpp` (same seed after restart,
`old_seeds` rotation).

## Standalone build

```bash
make build
```

The standalone firmware owns its Wi-Fi setup, serial `NUKE` wipe, Arduino
`WebServer` and `/reboot`. It runs password mode only. Its EEPROM layout
changed with this version: an old EEPROM image is reported as an unrecognized
record and not used. Wipe it with `NUKE` on the serial console to start over.
The standalone sources were updated but not compiled in this change.

## References

- Tang reference implementation: https://github.com/latchset/tang
- ESPHome external components: https://esphome.io/components/external_components/
- ESPHome web server: https://esphome.io/components/web_server/
