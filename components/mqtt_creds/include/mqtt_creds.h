#pragma once

#include <cstddef>

extern "C" {
#include "esp_err.h"
}

namespace mqtt_creds {

esp_err_t init(bool allow_provision_from_embedded);

// Public (non-secret) materials can stay embedded
const char* ca_pem();
const char* control_pub_pem();

// Secret / device-unique materials come from NVS
const char* client_crt_pem();
const char* client_key_pem();

} // namespace mqtt_creds
