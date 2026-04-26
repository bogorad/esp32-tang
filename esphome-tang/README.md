# ESPHome Tang Demo

This directory contains the ESPHome-facing demo assets for this fork.

Upstream `upstream/main` is the original ESP32 Tang firmware. The current tree
adds an ESPHome external component, a shared Tang core, signed advertisements,
`/rec/{kid}` recovery routing, Docker-based ESPHome compilation, and a small
Clevis round-trip demo. Those demo-specific files are kept here so the repo
root stays focused on the shared firmware and component source.

## Files

- `tang_server.yaml`: Minimal local ESPHome example using `../components`.
- `esp32tang.yaml`: Full ESPHome example using the GitHub external component.
- `secrets.yaml`: Demo-only ESPHome secrets. Replace these before flashing.
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
`/work/esphome-tang/esphome-compile.sh`. The script copies the local component
sources into a temporary ESPHome project and writes compile-only secrets there.

## Live Clevis Demo

After flashing a device with the ESPHome config and confirming HTTP port 80 is
reachable:

```bash
esphome-tang/tang-init-demo.sh http://<esphome-address> 'your-tang-initial-password'
```

The password is the `tang_initial_password` used when the device was compiled.
It is not the ESPHome web password. The script fetches `/pub`, activates the
Tang server, fetches `/adv/`, then runs a Clevis encrypt/decrypt round trip.

Required local commands:

```text
curl
jose
clevis
```
