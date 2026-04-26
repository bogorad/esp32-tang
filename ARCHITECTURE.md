# Architecture

Tang protocol behavior belongs in the shared core. Platform behavior belongs in
thin adapters.

The shared core should expose HTTP-independent operations. Adapters translate
their platform request, response, storage, clock, and lifecycle APIs into those
operations.

## Repository Boundaries

```text
src/                    shared Tang protocol, crypto, and storage interfaces
standalone/             Arduino lifecycle, WebServer adapter, Wi-Fi, serial
components/tang_server  ESPHome schema, Component wrapper, AsyncWebHandler adapter
main/                   standalone entry point glue
```

`main/` depends on `standalone/`. `standalone/` depends on `src/`.
`components/tang_server/` depends on `src/`.

`src/` must not depend on `main/`, `standalone/`, or `components/tang_server/`.

## Shared Core Rules

Keep shared Tang behavior in `src/`:

- activation and deactivation state
- key lifetime handling
- Tang request dispatch and response decisions
- JWK, JOSE, ECDH, AES-GCM, Concat KDF, and base64url helpers
- runtime Tang and admin key material
- storage-facing interfaces for key records and local encrypted data

Shared code should use small interfaces for external services, such as storage,
time, logging, request, and response types. It should not own platform globals.

Forbidden in `src/`:

- ESPHome headers
- Arduino `WebServer` headers
- standalone Wi-Fi setup
- serial command handling
- ESP-IDF or Arduino task bootstrap code
- EEPROM layout constants for a specific backend
- broad `#ifdef ESPHOME` protocol branches

If shared code needs platform data, add or reuse a narrow interface. Do not add
platform includes to the shared core.

## Adapter Rules

Adapters own platform integration only. They should not fork Tang protocol
logic.

The standalone adapter owns:

- Arduino `setup()` and `loop()`
- `WebServer` routing and response sending
- standalone Wi-Fi AP/STA fallback
- serial commands, including local wipe commands
- ESP-IDF and Arduino task bridge code
- EEPROM-backed storage implementation

The ESPHome adapter owns:

- YAML schema and code generation
- `Component` lifecycle integration
- registration with ESPHome `web_server_base`
- `AsyncWebHandler` request and response plumbing
- ESPHome storage integration
- ESPHome automations and Home Assistant notification hooks

Both adapters should call the same shared-core operations for `/adv`, `/pub`,
`/activate`, `/deactivate`, and future recovery work.

## Ownership Notes

Current HTTP handlers are platform-bound wrappers. Their request parsing and
response sending stay in adapters. Advertisement generation, public-key
formatting, activation orchestration, deactivation behavior, and crypto helpers
move behind shared-core or shared-crypto APIs.

Current EEPROM constants and raw persistence routines are storage-adapter
details. The shared core should ask a storage interface for admin keys, Tang
keys, encrypted local key data, and wipe operations.

No current declaration moves directly into ESPHome. ESPHome gets its own adapter
over the shared core instead of reusing Arduino `WebServer`, standalone Wi-Fi,
serial wipe, or ESP-IDF Arduino bootstrap code.
