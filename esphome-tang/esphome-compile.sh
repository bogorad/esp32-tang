#!/usr/bin/env bash

WORK_ROOT="${WORK_ROOT:-/work}"
BUILD_ROOT="${BUILD_ROOT:-/tmp/esp32-tang-esphome}"
# Usage: esphome-compile.sh [tang_server.yaml|tang_server_unattended.yaml]
CONFIG_NAME="${1:-tang_server.yaml}"
CONFIG_DIR="${BUILD_ROOT}/esphome-tang"
CONFIG_FILE="${CONFIG_DIR}/${CONFIG_NAME}"
SECRETS_FILE="${CONFIG_DIR}/secrets.yaml"

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

if [ ! -f "${WORK_ROOT}/esphome-tang/${CONFIG_NAME}" ]; then
  fail "missing ${WORK_ROOT}/esphome-tang/${CONFIG_NAME}"
fi

if [ ! -d "${WORK_ROOT}/components" ]; then
  fail "missing ${WORK_ROOT}/components"
fi

rm -rf "${BUILD_ROOT}"
if [ "$?" -ne 0 ]; then
  fail "failed to remove ${BUILD_ROOT}"
fi

mkdir -p "${CONFIG_DIR}"
if [ "$?" -ne 0 ]; then
  fail "failed to create ${CONFIG_DIR}"
fi

cp -rf "${WORK_ROOT}/components" "${BUILD_ROOT}/components"
if [ "$?" -ne 0 ]; then
  fail "failed to copy ESPHome components"
fi

if [ ! -d "${WORK_ROOT}/src" ]; then
  fail "missing ${WORK_ROOT}/src"
fi

cp -f "${WORK_ROOT}"/src/*.h "${BUILD_ROOT}/components/tang_server/"
if [ "$?" -ne 0 ]; then
  fail "failed to copy shared Tang headers"
fi

cp -f "${WORK_ROOT}"/src/*.cpp "${BUILD_ROOT}/components/tang_server/"
if [ "$?" -ne 0 ]; then
  fail "failed to copy shared Tang sources"
fi

cp -f "${WORK_ROOT}/esphome-tang/${CONFIG_NAME}" "${CONFIG_FILE}"
if [ "$?" -ne 0 ]; then
  fail "failed to copy ESPHome example config"
fi

cat > "${SECRETS_FILE}" <<'SECRETS'
wifi_ssid: compile-only
wifi_password: compile-only
tang_initial_password: compile-only
# Compile-only seed (not a real secret; never flash it).
tang_seed: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
SECRETS
if [ "$?" -ne 0 ]; then
  fail "failed to write compile-only ESPHome secrets"
fi

esphome compile "${CONFIG_FILE}"
status="$?"
if [ "${status}" -ne 0 ]; then
  exit "${status}"
fi
