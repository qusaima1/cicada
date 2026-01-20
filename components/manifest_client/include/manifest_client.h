#pragma once

#include "update_manager.h"

extern "C" {
#include "esp_err.h"
}

namespace ota {

// Fetches and parses https://.../manifest.json into ota::Manifest
class ManifestHttpsClient : public IManifestSource {
public:
    explicit ManifestHttpsClient(const char* manifest_url);

    esp_err_t fetch(Manifest& out) override;

private:
    const char* manifest_url_;

    static bool starts_with_https(const char* s);
    static bool hex_to_bytes_32(const char* hex64, uint8_t out32[32]);
};

} // namespace ota
