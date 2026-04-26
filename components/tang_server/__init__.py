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

tang_server_ns = cg.esphome_ns.namespace("tang_server")
TangServerComponent = tang_server_ns.class_("TangServerComponent", cg.Component)

DEPENDENCIES = ["web_server_base"]

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(TangServerComponent),
        cv.Required(CONF_INITIAL_PASSWORD): cv.string_strict,
        cv.Optional(CONF_KEY_LIFETIME, default="1h"): cv.positive_time_period_milliseconds,
        cv.Optional(CONF_NOTIFY_REQUESTS, default=False): cv.boolean,
        cv.Optional(CONF_ON_REQUEST): automation.validate_automation({}),
        cv.Optional(CONF_ON_ACTIVATE): automation.validate_automation({}),
        cv.Optional(CONF_ON_DEACTIVATE): automation.validate_automation({}),
        cv.Optional(CONF_ON_RECOVERY): automation.validate_automation({}),
    }
).extend(cv.COMPONENT_SCHEMA)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    cg.add(var.set_initial_password(config[CONF_INITIAL_PASSWORD]))
    cg.add(var.set_key_lifetime(config[CONF_KEY_LIFETIME].total_milliseconds))
    cg.add(var.set_notify_requests(config[CONF_NOTIFY_REQUESTS]))

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
