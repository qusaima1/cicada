idf_component_register(
    SRCS "cicada_mqtt.cpp"
    INCLUDE_DIRS "include"
    REQUIRES mqtt mqtt_creds cicada_cmd
)
