import esphome.codegen as cg
from esphome.components import sensor
import esphome.config_validation as cv
from esphome.const import (
    ENTITY_CATEGORY_DIAGNOSTIC,
    ICON_COUNTER,
    STATE_CLASS_MEASUREMENT,
    STATE_CLASS_TOTAL_INCREASING,
    UNIT_EMPTY,
)

from . import CONF_TANG_SERVER_ID, TangServerComponent

CONF_ACTIVATION_COUNT = "activation_count"
CONF_LAST_STATUS = "last_status"
CONF_RECOVERY_COUNT = "recovery_count"
CONF_REQUEST_COUNT = "request_count"

COUNTER_SCHEMA = sensor.sensor_schema(
    unit_of_measurement=UNIT_EMPTY,
    accuracy_decimals=0,
    icon=ICON_COUNTER,
    state_class=STATE_CLASS_TOTAL_INCREASING,
    entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_TANG_SERVER_ID): cv.use_id(TangServerComponent),
        cv.Optional(CONF_REQUEST_COUNT): COUNTER_SCHEMA,
        cv.Optional(CONF_ACTIVATION_COUNT): COUNTER_SCHEMA,
        cv.Optional(CONF_RECOVERY_COUNT): COUNTER_SCHEMA,
        cv.Optional(CONF_LAST_STATUS): sensor.sensor_schema(
            unit_of_measurement=UNIT_EMPTY,
            accuracy_decimals=0,
            state_class=STATE_CLASS_MEASUREMENT,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
        ),
    }
)


async def to_code(config):
    parent = await cg.get_variable(config[CONF_TANG_SERVER_ID])

    for key in (
        CONF_REQUEST_COUNT,
        CONF_ACTIVATION_COUNT,
        CONF_RECOVERY_COUNT,
        CONF_LAST_STATUS,
    ):
        if conf := config.get(key):
            sens = await sensor.new_sensor(conf)
            cg.add(getattr(parent, f"set_{key}_sensor")(sens))
