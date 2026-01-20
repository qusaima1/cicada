idf_component_register(
    SRCS "trust_store.cpp"
    INCLUDE_DIRS
        "include"
    EMBED_TXTFILES "server.crt"
)
