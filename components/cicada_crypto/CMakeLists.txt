idf_component_register(
    SRCS "cicada_crypto.cpp"
    INCLUDE_DIRS "include"
    REQUIRES mbedtls json update_manager
    EMBED_TXTFILES "root_pub.pem"
)
