import esphome.codegen as cg
from esphome.components import binary_sensor
import esphome.config_validation as cv
from esphome.const import DEVICE_CLASS_CONNECTIVITY, ENTITY_CATEGORY_DIAGNOSTIC

from . import CONF_TANG_SERVER_ID, TangServerComponent

CONF_ACTIVE = "active"

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_TANG_SERVER_ID): cv.use_id(TangServerComponent),
        cv.Optional(CONF_ACTIVE): binary_sensor.binary_sensor_schema(
            device_class=DEVICE_CLASS_CONNECTIVITY,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
        ),
    }
)


async def to_code(config):
    parent = await cg.get_variable(config[CONF_TANG_SERVER_ID])

    if conf := config.get(CONF_ACTIVE):
        sens = await binary_sensor.new_binary_sensor(conf)
        cg.add(parent.set_active_binary_sensor(sens))
