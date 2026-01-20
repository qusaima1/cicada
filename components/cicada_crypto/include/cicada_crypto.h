#pragma once

#include "update_manager.h"

extern "C" {
#include "esp_err.h"
#include "cJSON.h"
}

namespace cicada {

// Verify Root-signed release cert and release-signed manifest payload.
// Returns ESP_OK only if both signatures are valid.
esp_err_t verify_signed_manifest(const ota::Manifest& m, const cJSON* cicada_obj);

} // namespace cicada
