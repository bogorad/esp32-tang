# ESPHome Tang Demo

This directory contains the ESPHome-facing demo assets for this fork.

Upstream `upstream/main` is the original ESP32 Tang firmware. The current tree
adds an ESPHome external component, a shared Tang core, signed advertisements,
`/rec/{kid}` recovery routing, Docker-based ESPHome compilation, and a small
Clevis round-trip demo. Those demo-specific files are kept here so the repo
root stays focused on the shared firmware and component source.

## Files

- `tang_server.yaml`, `tang_server_unattended.yaml`: Minimal local examples
  using `../components` (password mode, unattended mode).
- `esp32tang.yaml`: Full password-mode example using the GitHub component.
- `esp32tang-unattended.yaml`: Full unattended example (seed-derived keys,
  active at boot). Read the threat model in the root README first.
- `secrets.sample.yaml`: Placeholders only. Copy it to `secrets.yaml` (which is
  git-ignored) and replace every value.
- `docker-compose.yml`: Runs ESPHome in Docker from this directory.
- `esphome-compile.sh`: Stages the local component and compiles the demo YAML.
- `tang-init-demo.sh`: Activates a running device and verifies Clevis
  encrypt/decrypt against it.

## Compile Demo

From the repo root:

```bash
docker compose -f esphome-tang/docker-compose.yml run --rm esphome
```

The compose file mounts the repo at `/work` and runs
`/work/esphome-tang/esphome-compile.sh` (password-mode example). Pass
`tang_server_unattended.yaml` as the argument to compile the unattended one. The script copies the local component
sources into a temporary ESPHome project and writes compile-only secrets there.

## Live Clevis Demo

After flashing a device with the ESPHome config and confirming HTTP port 80 is
reachable:

```bash
esphome-tang/tang-init-demo.sh http://<esphome-address> 'your-tang-initial-password'
```

This script is for password mode. The password is the `tang_initial_password`
used when the device was compiled; it is not the ESPHome web password. The
script fetches `/pub`, activates the Tang server, fetches `/adv/`, then runs a
Clevis encrypt/decrypt round trip. For an unattended device skip activation:
`clevis encrypt tang '{"url":"http://<esphome-address>"}'` works at once.

Required local commands:

```text
curl
jose
clevis
```
