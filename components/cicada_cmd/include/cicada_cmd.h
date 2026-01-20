#pragma once
#include <cstdint>

extern "C" {
#include "esp_err.h"
}

namespace cicada_cmd {

esp_err_t init();  // NVS init for replay counter
bool verify_and_update_counter(const char* local_device_id, const char* json, char* out_cmd, size_t out_cmd_sz, char* out_args_json, size_t out_args_sz);

} // namespace cicada_cmd
