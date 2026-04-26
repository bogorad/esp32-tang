# ESP32 Tang Server

Experimental Tang server firmware for ESP32. The repo now has two build
surfaces that share one Tang core:

- Standalone ESP-IDF/Arduino firmware.
- ESPHome external component under `components/tang_server`.

The shared Tang logic lives in `src/`. Standalone glue lives in `standalone/`
and ESPHome glue lives in `components/tang_server/`.

## Current Status

This implementation is still experimental. It supports ESPHome compilation,
standalone compilation, Tang advertisement/admin endpoints, activation and
deactivation flow plumbing, ESPHome automations, and optional ESPHome status
entities.

Runtime curl validation still requires a real ESP32 on the network. Protocol
compatibility work has advanced, but live Clevis interoperability remains a
separate validation step.

## Standalone Build

Build the original standalone firmware from this repo:

```bash
make build
```

The expected firmware artifact is:

```text
build/esp32-tang.bin
```

Standalone firmware owns its Wi-Fi setup, serial `NUKE` handling, Arduino
`WebServer`, and `/reboot` endpoint.

## ESPHome Build

The ESPHome integration is an external component named `tang_server`.
ESPHome owns Wi-Fi, logging, OTA, native API, and the HTTP server lifecycle.
The component registers Tang routes through ESPHome `web_server_base`.

Compile the included example with Docker:

```bash
docker compose run --rm esphome
```

That command uses `scripts/esphome-compile.sh`, stages compile-only secrets in
`/tmp` inside the container, and compiles `examples/tang_server.yaml`.

Use this shape from an ESPHome YAML file:

```yaml
external_components:
  - source:
      type: local
      path: ./components
    components: [tang_server]

tang_server:
  id: tang_component
  initial_password: !secret tang_initial_password
  key_lifetime: 1h
```

Required ESPHome secrets for the included example:

```yaml
wifi_ssid: "..."
wifi_password: "..."
tang_web_user: "..."
tang_web_password: "..."
tang_initial_password: "..."
```

## HTTP Endpoints

The ESPHome and standalone adapters both route Tang behavior through the shared
core.

- `GET /pub`: return the admin public key JWK used by the activation flow.
- `GET /adv`: return the active Tang advertisement.
- `POST /activate`: accept a JWE body and activate the stored Tang key.
- `GET /deactivate`: deactivate the in-memory Tang key.
- `POST /deactivate`: accept a JWE body, re-encrypt stored Tang key material,
  and deactivate.
- `POST /rec/{kid}`: perform the recovery handoff for a known active key id.
- `GET /reboot`: standalone-only.

Example activation flow:

```bash
curl http://<esp-ip>/pub > server_pub.jwk
echo -n "change-me" | jose jwe enc -I- -k server_pub.jwk -o request.jwe -i '{"protected":{"enc":"A128GCM"}}'
curl -X POST -H "Content-Type: application/json" -d @request.jwe http://<esp-ip>/activate
curl http://<esp-ip>/adv
```

## ESPHome Notifications

The component exposes ESPHome automations so notifications stay opt-in.

```yaml
api:

tang_server:
  id: tang_component
  initial_password: !secret tang_initial_password
  key_lifetime: 1h
  on_request:
    then:
      - homeassistant.event:
          event: esphome.tang_request
          data:
            path: !lambda "return path;"
            method: !lambda "return method;"
            status: !lambda "return status;"
```

Available triggers:

- `on_request(path, method, status)`
- `on_activate(success)`
- `on_deactivate()`
- `on_recovery(success)`

Optional ESPHome entities are also available for status dashboards:

- `binary_sensor`: `active`
- `sensor`: `request_count`, `activation_count`, `recovery_count`, `last_status`
- `text_sensor`: `last_path`, `last_method`, `last_error`

## Protocol Limits

This is not yet a finished security product.

- Live ESP32 curl smoke tests still need hardware and an activation JWE.
- Live Clevis bind/recover tests still need a reachable ESP32.
- Signed advertisement work currently needs a maintained key model decision for
  admin-key reuse versus a dedicated signing key.
- Tang key rotation is tracked separately.
- Password-derived local encryption remains a development design until the KDF
  and storage model are hardened.

## References

- Tang reference implementation: https://github.com/latchset/tang
- ESPHome external components: https://esphome.io/components/external_components/
- ESPHome web server: https://esphome.io/components/web_server/
