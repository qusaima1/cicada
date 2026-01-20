idf_component_register(
    SRCS "transport_https_ota.cpp"
    INCLUDE_DIRS
        "include"
    REQUIRES esp_https_ota esp_http_client app_update trust_store update_manager spi_flash mbedtls
)
