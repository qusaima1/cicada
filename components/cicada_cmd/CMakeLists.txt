idf_component_register(
    SRCS "cicada_cmd.cpp"
    INCLUDE_DIRS "include"
    REQUIRES mbedtls json nvs_flash mqtt_creds
)
