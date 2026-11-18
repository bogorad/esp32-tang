import re

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome import automation
from esphome.const import CONF_ID

CONF_INITIAL_PASSWORD = "initial_password"
CONF_KEY_LIFETIME = "key_lifetime"
CONF_NOTIFY_REQUESTS = "notify_requests"
CONF_ON_ACTIVATE = "on_activate"
CONF_ON_DEACTIVATE = "on_deactivate"
CONF_ON_RECOVERY = "on_recovery"
CONF_ON_REQUEST = "on_request"
CONF_TANG_SERVER_ID = "tang_server_id"
CONF_UNATTENDED = "unattended"
CONF_SEED = "seed"
CONF_OLD_SEEDS = "old_seeds"
CONF_RESET_TOKEN = "reset_token"

# Seed rules. Keep in sync with tang::decode_seed_hex in tang_crypto.cpp.
MIN_SEED_BYTES = 32
MAX_SEED_BYTES = 128
MIN_SEED_DISTINCT_BYTES = 8
MAX_PASSWORD_BYTES = 128  # activation JWE plaintext buffer in tang_core.cpp
DEFAULT_KEY_LIFETIME = "1h"

tang_server_ns = cg.esphome_ns.namespace("tang_server")
TangServerComponent = tang_server_ns.class_("TangServerComponent", cg.Component)

DEPENDENCIES = ["web_server_base"]

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def seed_string(value):
    """A seed is hex text: at least 64 hex chars (32 bytes), not degenerate."""
    value = cv.string_strict(value)
    if not _HEX_RE.match(value):
        raise cv.Invalid(
            "seed must be hexadecimal (0-9, a-f), e.g. the output of "
            "'openssl rand -hex 32'"
        )
    if len(value) % 2 != 0:
        raise cv.Invalid("seed must have an even number of hex digits")
    nbytes = len(value) // 2
    if nbytes < MIN_SEED_BYTES:
        raise cv.Invalid(
            f"seed has only {nbytes} bytes; need at least {MIN_SEED_BYTES} "
            f"bytes ({MIN_SEED_BYTES * 2} hex chars), e.g. 'openssl rand -hex 32'"
        )
    if nbytes > MAX_SEED_BYTES:
        raise cv.Invalid(f"seed is longer than {MAX_SEED_BYTES} bytes")
    if len(set(bytes.fromhex(value))) < MIN_SEED_DISTINCT_BYTES:
        raise cv.Invalid(
            "seed looks degenerate (too few distinct bytes); "
            "generate it with 'openssl rand -hex 32'"
        )
    return value


def password_string(value):
    value = cv.string_strict(value)
    if not value:
        raise cv.Invalid("initial_password must not be empty")
    if len(value.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise cv.Invalid(f"initial_password is longer than {MAX_PASSWORD_BYTES} bytes")
    return value


def _validate_modes(config):
    if config[CONF_UNATTENDED]:
        if CONF_SEED not in config:
            raise cv.Invalid(
                f"'{CONF_SEED}' is required when '{CONF_UNATTENDED}: true'",
                path=[CONF_SEED],
            )
        for forbidden in (CONF_INITIAL_PASSWORD, CONF_KEY_LIFETIME, CONF_RESET_TOKEN):
            if forbidden in config:
                raise cv.Invalid(
                    f"'{forbidden}' is not used in unattended mode "
                    "(keys come from the seed, never expire, nothing is stored)",
                    path=[forbidden],
                )
        seen = {config[CONF_SEED].lower()}
        for old in config.get(CONF_OLD_SEEDS, []):
            if old.lower() in seen:
                raise cv.Invalid(
                    f"'{CONF_OLD_SEEDS}' contains a duplicate or the current seed",
                    path=[CONF_OLD_SEEDS],
                )
            seen.add(old.lower())
    else:
        if CONF_INITIAL_PASSWORD not in config:
            raise cv.Invalid(
                f"'{CONF_INITIAL_PASSWORD}' is required unless "
                f"'{CONF_UNATTENDED}: true'",
                path=[CONF_INITIAL_PASSWORD],
            )
        for forbidden in (CONF_SEED, CONF_OLD_SEEDS):
            if forbidden in config:
                raise cv.Invalid(
                    f"'{forbidden}' needs '{CONF_UNATTENDED}: true'",
                    path=[forbidden],
                )
    return config


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(TangServerComponent),
            cv.Optional(CONF_UNATTENDED, default=False): cv.boolean,
            cv.Optional(CONF_SEED): seed_string,
            cv.Optional(CONF_OLD_SEEDS): cv.ensure_list(seed_string),
            cv.Optional(CONF_INITIAL_PASSWORD): password_string,
            cv.Optional(CONF_KEY_LIFETIME): cv.positive_time_period_milliseconds,
            cv.Optional(CONF_RESET_TOKEN): cv.uint32_t,
            cv.Optional(CONF_NOTIFY_REQUESTS, default=False): cv.boolean,
            cv.Optional(CONF_ON_REQUEST): automation.validate_automation({}),
            cv.Optional(CONF_ON_ACTIVATE): automation.validate_automation({}),
            cv.Optional(CONF_ON_DEACTIVATE): automation.validate_automation({}),
            cv.Optional(CONF_ON_RECOVERY): automation.validate_automation({}),
        }
    ).extend(cv.COMPONENT_SCHEMA),
    _validate_modes,
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    cg.add(var.set_unattended(config[CONF_UNATTENDED]))
    cg.add(var.set_notify_requests(config[CONF_NOTIFY_REQUESTS]))

    if config[CONF_UNATTENDED]:
        cg.add(var.set_seed(config[CONF_SEED]))
        for old in config.get(CONF_OLD_SEEDS, []):
            cg.add(var.add_old_seed(old))
    else:
        cg.add(var.set_initial_password(config[CONF_INITIAL_PASSWORD]))
        lifetime = config.get(
            CONF_KEY_LIFETIME, cv.positive_time_period_milliseconds(DEFAULT_KEY_LIFETIME)
        )
        # 64-bit: lifetimes above 49 days do not wrap.
        cg.add(
            var.set_key_lifetime_ms(
                cg.RawExpression(f"{int(lifetime.total_milliseconds)}ULL")
            )
        )
        cg.add(var.set_reset_token(config.get(CONF_RESET_TOKEN, 0)))

    for conf in config.get(CONF_ON_REQUEST, []):
        await automation.build_callback_automation(
            var,
            "add_on_request_callback",
            [(cg.std_string, "path"), (cg.std_string, "method"), (cg.int_, "status")],
            conf,
        )
    for conf in config.get(CONF_ON_ACTIVATE, []):
        await automation.build_callback_automation(
            var, "add_on_activate_callback", [(cg.bool_, "success")], conf
        )
    for conf in config.get(CONF_ON_DEACTIVATE, []):
        await automation.build_callback_automation(
            var, "add_on_deactivate_callback", [], conf
        )
    for conf in config.get(CONF_ON_RECOVERY, []):
        await automation.build_callback_automation(
            var, "add_on_recovery_callback", [(cg.bool_, "success")], conf
        )
