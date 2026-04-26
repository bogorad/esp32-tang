idf_component_register(SRCS "main.cpp"
                            "../src/tang_core.cpp"
                            "../src/tang_crypto.cpp"
                            "../standalone/arduino_app.cpp"
                            "../standalone/arduino_http_server.cpp"
                            "../standalone/eeprom_tang_storage.cpp"
                       INCLUDE_DIRS "." "../src" "../standalone"
                       REQUIRES arduino-esp32 mbedtls)
