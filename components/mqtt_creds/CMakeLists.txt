set(embed_files
    "cicada_ca.crt"
    "control_pub.pem"
)

if(CONFIG_CICADA_PROVISION_FROM_EMBEDDED)
    list(APPEND embed_files "device.crt" "device.key")
endif()

idf_component_register(
    SRCS "mqtt_creds.cpp"
    INCLUDE_DIRS "include"
    REQUIRES nvs_flash
    EMBED_TXTFILES ${embed_files}
)
