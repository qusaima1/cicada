#pragma once
#include <cstddef>

namespace trust_store {
    const char* server_cert_pem();
    size_t server_cert_pem_len();
}
