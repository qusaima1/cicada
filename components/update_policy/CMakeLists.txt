idf_component_register(
    SRCS "version_policy.cpp"
    INCLUDE_DIRS
        "include"
    REQUIRES update_manager
             esp_netif
             esp_event
             esp_wifi
             nvs_flash
             efuse
)