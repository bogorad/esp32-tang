# Guide: network-bound disk unlock with ESP32 Tang

This guide explains the idea, the two server modes, the ESPHome setup, the
Clevis client side, and the usual problems. All host names and addresses here
are placeholders (`tang1.lan`, `192.0.2.10`). Replace them with your own.

## 1. Tang and Clevis in plain words

- **Tang** is a small HTTP server. It holds a private key and does one job:
  it helps a client recover a secret.
- **Clevis** is the client. It runs on the machine with the encrypted disk.
  `clevis luks bind` stores a small encrypted token in the LUKS header. At boot,
  `clevis luks unlock` reads the token, asks the Tang server for help, and gets
  the disk key back.

How the exchange works (McCallum-Relyea key exchange):

1. At bind time Clevis fetches the server's public keys (`GET /adv`) and checks
   the signature. It makes a fresh client key pair and combines it with the
   server's exchange key. The result is the secret that protects the disk key.
   Clevis then forgets the secret and keeps only the client public key in the
   token.
2. At unlock time Clevis sends a blinded form of that client public key to the
   server (`POST /rec/<kid>`). The server multiplies it with its private key and
   answers. Clevis removes the blinding and has the secret again.
3. The server never sees the disk key and never stores anything per client. It
   cannot read the disk. It only answers a math question.

So the disk opens only when a Tang server that holds the right private key is
reachable. A thief who steals only the disk, or only the server, gets nothing.
A thief who gets both, and a network where the server answers, can unlock.

## 2. Choose a mode

| | Unattended (seed) | Password / activation |
|---|---|---|
| Keys | derived from `seed` at each boot | random, stored in flash |
| After boot | active at once | needs `POST /activate` with the password |
| Power loss | recovers with nobody present | stays inactive until someone activates |
| Flash writes | none | key record, reset token |
| Use it when | the disk must unlock by itself after an outage | a person or script can activate after each boot |

### Unattended mode: threat model

- The seed is in the firmware image. Whoever gets the flash, the firmware
  binary, or the build directory has the Tang keys.
- With the keys and the disk they can unlock it. With Clevis `sss` and `t=1`,
  **any one** device plus the disk is enough.
- Enable ESP32 flash encryption and secure boot on devices you do not control
  physically.
- Keep each seed offline (backup) and out of git. Use **one seed per device**.
  After a loss or theft, never reuse that seed.
- Use `t=2` of 3 if one stolen device must not be enough. You then need two
  devices up at boot.
- Traffic is plain HTTP. Tang is safe against someone who only watches the
  network. Keep the servers on a network you trust against active attackers.

### Password mode: threat model

- The exchange key is in flash, encrypted with a key made from
  `initial_password` (PBKDF2-HMAC-SHA256, random salt). Flash extraction allows
  an offline guess of the password, so use a long random password and enable
  flash encryption if extraction is in scope.
- While active, the key is in RAM. It is erased after `key_lifetime` (default
  1 h) or on `POST /deactivate`.
- The activation message can be replayed by someone who captured it. They do
  not learn a key. Keep the management network trusted.
- The cost: after a power outage the server is inactive and the disk does not
  unlock until someone activates it.

Details of the key derivation, rotation and record handling are in the
[README](../README.md).

## 3. ESPHome setup (unattended), step by step

1. Make a seed. One per device:

   ```bash
   openssl rand -hex 32
   ```

   It must be hex, 32 to 128 bytes (64 to 256 hex characters), with at least 8
   distinct byte values. The build fails otherwise.

2. Put it in `secrets.yaml` (git-ignored; copy `esphome-tang/secrets.sample.yaml`).
   Use one key per device:

   ```yaml
   wifi_ssid: "<ssid>"
   wifi_password: "<password>"
   tang1_seed: "<seed>"
   tang2_seed: "<seed>"
   ```

3. Make a reusable package file, `tang.yaml`, next to your device files:

   ```yaml
   # tang.yaml - needs the variable `tang_seed`
   api:
     reboot_timeout: 0s       # keep serving without Home Assistant

   web_server:
     port: 80

   external_components:
     - source: github://bogorad/esp32-tang@main
       components: [tang_server]

   tang_server:
     id: tang_component
     unattended: true
     seed: ${tang_seed}
   ```

4. Include it in each device file with its own seed:

   ```yaml
   packages:
     tang: !include
       file: tang.yaml
       vars:
         tang_seed: !secret tang1_seed
   ```

   Why the variable: `!secret` cannot take a substitution. You cannot write
   `!secret ${name}_seed`. Pass the secret as an include variable instead.

5. Also set `wifi: reboot_timeout: 0s` in the device file. Why `api:
   reboot_timeout: 0s`: ESPHome by default reboots a device after 15 minutes
   without a Home Assistant API client. A Tang server must keep serving when
   Home Assistant is down.

6. Compile and flash with ESPHome. Then check:

   ```bash
   clevis encrypt tang '{"url":"http://tang1.lan"}' <<<'test' | clevis decrypt
   ```

   It should print `test`.

Complete examples: `esphome-tang/esp32tang-unattended.yaml` and
`esphome-tang/tang_server_unattended.yaml`.

### Verified hardware

ESP32-C6 (M5Stack NanoC6) and classic ESP32 (M5Stack Atom), ESPHome 2026.9.1,
ESP-IDF framework. On the C6, with Bluetooth proxy and web server, flash use
was about 87% of the 1.75 MB app partition. If flash is tight, remove
components you do not need.

## 4. Clevis client side

### Bind with several servers

Use Shamir secret sharing (`sss`) so one dead server does not block boot:

```bash
clevis luks bind -d /dev/<disk-partition> sss '{
  "t": 1,
  "pins": {
    "tang": [
      {"url": "http://tang1.lan"},
      {"url": "http://tang2.lan"},
      {"url": "http://tang3.lan"}
    ]
  }
}'
```

`t` is how many servers must answer. `t=1` gives availability. `t=2` also
means one stolen device is not enough.

### URLs

- Prefer DNS names that your network resolves, or fixed IPs. Give each device a
  static DHCP reservation so the address does not change.
- mDNS names (`*.local`) do not work in an initrd. There is no resolver for
  them at that stage.
- A trailing slash in the URL is fine. Clevis builds `<url>/adv/<thp>`, and the
  server accepts `//adv` and a trailing slash.

### Rebind and rotate

- `clevis luks regen -d /dev/<disk-partition> -s <slot>` makes a new binding
  with the same configuration (new client key, current server keys).
- To rotate a seed: set the new `seed`, move the old one to `old_seeds`, flash,
  then `clevis luks regen` each disk. Remove the old seed on a later flash.
  `old_seeds` keep existing bindings working but are not advertised.

### LUKS2 header capacity

Each Tang binding uses about 1.5 KB of token space. The default 16 KiB LUKS2
metadata area holds only about 6 bindings, so several `sss` bindings fill it
fast. Format with a bigger area:

```bash
cryptsetup luksFormat --type luks2 --luks2-metadata-size=1m /dev/<disk-partition>
```

You can set this only at `luksFormat`. An existing disk needs a new header
(back up and reformat).

### NixOS

Use `boot.initrd.clevisLuksAskpass`. It retries until a Tang server answers.
`boot.initrd.clevis.devices` tries once, so a slow network at boot means a
failed unlock. Add `boot.initrd.network.ssh` as a fallback so you can unlock by
hand. Make sure the initrd has working networking (DHCP or a static address).

## 5. Tests

```bash
make test           # host tests: core, crypto vectors, jose, real Clevis round trips
make test-esphome   # ESPHome config validation (needs esphome)
```

- `make test` runs `tests/run.sh`. It needs cmake, a C++17 compiler, mbedTLS 3.x,
  `jose`, `clevis` and `curl`. If a tool is missing and `nix` exists, it
  re-runs itself in `nix shell`. Otherwise a missing tool is an error.
- Sanitizers: `TANG_TEST_SANITIZE=address,undefined TANG_TEST_BUILD_DIR=build-asan make test`
  (use `thread` for the thread sanitizer, with its own build directory).
- To select tests, pass a name filter: `tests/run.sh <filter>`.

## 6. Troubleshooting

| Symptom | Meaning and fix |
|---|---|
| `403` on `/adv` or `/rec/<kid>` | Password mode and the server is inactive. Activate it, or use unattended mode. |
| `404` on `/pub`, `/activate`, `/deactivate` | Unattended mode has no such endpoints. |
| `404` on `/adv/<thp>` | The thumbprint is not a key of this server (wrong or rotated key). `404` on `/rec/<kid>`: the key id is not active. Re-bind with `clevis luks regen`. |
| `405` | Wrong HTTP method (for example `GET /deactivate`). |
| `503` | The core did not start. Read the device log. In password mode this includes a stored record that fails validation; see `reset_token` in the README. |
| `429` | Too many wrong passwords. Wait for the back-off (at most 5 min). |
| Trailing slash or `//adv` fails | Fixed. Paths are normalized before routing. Update the firmware. |
| POST works with Clevis but not with `curl -d` | ESPHome consumes form-encoded bodies. Send `Content-Type: application/json`. |
| ESPHome before 2026.8 | The component reads the POST body from the socket when ESPHome never calls `handleBody()`. Works, but 2026.8 or later is better. |
| Device reboots every 15 min | Home Assistant is absent. Set `reboot_timeout: 0s` for `api:` and `wifi:`. |
| Build fails on flash size | The app partition is full. Remove other components (Bluetooth proxy, extra sensors). |
