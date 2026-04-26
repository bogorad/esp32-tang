import esphome.codegen as cg
from esphome.components import text_sensor
import esphome.config_validation as cv
from esphome.const import ENTITY_CATEGORY_DIAGNOSTIC

from . import CONF_TANG_SERVER_ID, TangServerComponent

CONF_LAST_ERROR = "last_error"
CONF_LAST_METHOD = "last_method"
CONF_LAST_PATH = "last_path"

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_TANG_SERVER_ID): cv.use_id(TangServerComponent),
        cv.Optional(CONF_LAST_PATH): text_sensor.text_sensor_schema(
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
        ),
        cv.Optional(CONF_LAST_METHOD): text_sensor.text_sensor_schema(
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
        ),
        cv.Optional(CONF_LAST_ERROR): text_sensor.text_sensor_schema(
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
        ),
    }
)


async def to_code(config):
    parent = await cg.get_variable(config[CONF_TANG_SERVER_ID])

    for key in (CONF_LAST_PATH, CONF_LAST_METHOD, CONF_LAST_ERROR):
        if conf := config.get(key):
            sens = await text_sensor.new_text_sensor(conf)
            cg.add(getattr(parent, f"set_{key}_text_sensor")(sens))
