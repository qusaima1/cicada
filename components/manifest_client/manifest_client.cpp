#include "manifest_client.h"

#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "esp_log.h"
#include "esp_http_client.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "cJSON.h"
}

#include "trust_store.h"
#include "cicada_crypto.h"

namespace ota {

static const char* TAG = "manifest_client";

// Retry policy
static constexpr int    MANIFEST_MAX_RETRIES  = 0;        // 0 = retry forever
static constexpr int    MANIFEST_TIMEOUT_MS   = 15000;    // per attempt
static constexpr int    BACKOFF_START_MS      = 1000;     // 1s
static constexpr int    BACKOFF_MAX_MS        = 30000;    // 30s
static constexpr size_t MAX_MANIFEST_BYTES    = 8192;

ManifestHttpsClient::ManifestHttpsClient(const char* manifest_url)
    : manifest_url_(manifest_url) {}

bool ManifestHttpsClient::starts_with_https(const char* s)
{
    return (s && std::strncmp(s, "https://", 8) == 0);
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

bool ManifestHttpsClient::hex_to_bytes_32(const char* hex64, uint8_t out32[32])
{
    if (!hex64) return false;
    if (std::strlen(hex64) != 64) return false;

    for (int i = 0; i < 64; ++i) {
        if (hex_nibble(hex64[i]) < 0) return false;
    }

    for (int i = 0; i < 32; ++i) {
        int hi = hex_nibble(hex64[i * 2]);
        int lo = hex_nibble(hex64[i * 2 + 1]);
        out32[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static int compute_backoff_ms(int attempt)
{
    int backoff = BACKOFF_START_MS;
    for (int i = 1; i < attempt; ++i) {
        if (backoff < BACKOFF_MAX_MS / 2) backoff *= 2;
        else backoff = BACKOFF_MAX_MS;
    }
    if (backoff > BACKOFF_MAX_MS) backoff = BACKOFF_MAX_MS;
    return backoff;
}

esp_err_t ManifestHttpsClient::fetch(Manifest& out)
{
    if (!manifest_url_ || !starts_with_https(manifest_url_)) {
        ESP_LOGE(TAG, "Manifest URL must be https://...");
        return ESP_ERR_INVALID_ARG;
    }

    int attempt = 0;
    esp_err_t last_err = ESP_FAIL;

    while (true) {
        attempt++;
        ESP_LOGW(TAG, "Manifest fetch attempt %d: %s", attempt, manifest_url_);

        esp_http_client_config_t cfg = {};
        cfg.url = manifest_url_;
        cfg.cert_pem = trust_store::server_cert_pem();
        cfg.timeout_ms = MANIFEST_TIMEOUT_MS;

        esp_http_client_handle_t client = esp_http_client_init(&cfg);
        if (!client) {
            ESP_LOGE(TAG, "esp_http_client_init failed");
            return ESP_ERR_NO_MEM;
        }

        esp_http_client_set_method(client, HTTP_METHOD_GET);

        // Use open/fetch_headers/read (do NOT mix perform + manual reads)
        esp_err_t err = esp_http_client_open(client, 0);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "HTTP open failed: %s (0x%x)", esp_err_to_name(err), (unsigned)err);
            esp_http_client_cleanup(client);
            last_err = err;
        } else {
            (void)esp_http_client_fetch_headers(client);
            const int status = esp_http_client_get_status_code(client);

            if (status != 200) {
                ESP_LOGE(TAG, "HTTP status %d", status);
                esp_http_client_close(client);
                esp_http_client_cleanup(client);
                last_err = ESP_FAIL;
            } else {
                std::string body;
                body.reserve(1024);

                std::vector<char> buf(512);
                bool read_failed = false;

                while (true) {
                    int r = esp_http_client_read(client, buf.data(), (int)buf.size());
                    if (r < 0) {
                        ESP_LOGE(TAG, "HTTP read failed");
                        read_failed = true;
                        break;
                    }
                    if (r == 0) break;

                    body.append(buf.data(), (size_t)r);
                    if (body.size() > MAX_MANIFEST_BYTES) {
                        ESP_LOGE(TAG, "Manifest too large");
                        esp_http_client_close(client);
                        esp_http_client_cleanup(client);
                        return ESP_ERR_NO_MEM;
                    }
                }

                esp_http_client_close(client);
                esp_http_client_cleanup(client);

                if (read_failed) {
                    last_err = ESP_FAIL;
                } else {
                    // Strip UTF-8 BOM if present
                    if (body.size() >= 3 &&
                        (uint8_t)body[0] == 0xEF &&
                        (uint8_t)body[1] == 0xBB &&
                        (uint8_t)body[2] == 0xBF) {
                        body.erase(0, 3);
                    }

                    if (body.empty()) {
                        ESP_LOGE(TAG, "Manifest body empty");
                        last_err = ESP_FAIL;
                    } else {
                        cJSON* root = cJSON_Parse(body.c_str());
                        if (!root) {
                            ESP_LOGE(TAG, "JSON parse failed. First 120 bytes: %.120s", body.c_str());
                            last_err = ESP_ERR_INVALID_RESPONSE;
                        } else {
                            const cJSON* j_version = cJSON_GetObjectItemCaseSensitive(root, "version");
                            const cJSON* j_secure  = cJSON_GetObjectItemCaseSensitive(root, "secure_version");
                            const cJSON* j_url     = cJSON_GetObjectItemCaseSensitive(root, "url");
                            const cJSON* j_size    = cJSON_GetObjectItemCaseSensitive(root, "size");
                            const cJSON* j_sha     = cJSON_GetObjectItemCaseSensitive(root, "sha256");

                            if (!cJSON_IsString(j_version) || !j_version->valuestring ||
                                !cJSON_IsString(j_url)     || !j_url->valuestring) {
                                ESP_LOGE(TAG, "Manifest missing required fields (version/url)");
                                last_err = ESP_ERR_INVALID_RESPONSE;
                            } else if (!starts_with_https(j_url->valuestring)) {
                                ESP_LOGE(TAG, "Firmware URL must be https://...");
                                last_err = ESP_ERR_INVALID_RESPONSE;
                            } else {
                                std::memset(&out, 0, sizeof(out));
                                std::snprintf(out.version, sizeof(out.version), "%s", j_version->valuestring);
                                std::snprintf(out.url, sizeof(out.url), "%s", j_url->valuestring);

                                out.secure_version = cJSON_IsNumber(j_secure) ? (uint32_t)j_secure->valuedouble : 0;
                                out.size          = cJSON_IsNumber(j_size)   ? (uint32_t)j_size->valuedouble   : 0;

                                if (cJSON_IsString(j_sha) && j_sha->valuestring && std::strlen(j_sha->valuestring) == 64) {
                                    if (!hex_to_bytes_32(j_sha->valuestring, out.sha256)) {
                                        ESP_LOGE(TAG, "Invalid sha256 format");
                                        last_err = ESP_ERR_INVALID_RESPONSE;
                                    } else {
                                        last_err = ESP_OK;
                                    }
                                } else {
                                    // sha256 optional for now; left as zeros
                                    std::memset(out.sha256, 0, sizeof(out.sha256));
                                    last_err = ESP_OK;
                                }
                            }
                                const cJSON* j_cicada = cJSON_GetObjectItemCaseSensitive(root, "cicada");
                                esp_err_t verr = cicada::verify_signed_manifest(out, j_cicada);
                                if (verr != ESP_OK) {
                                ESP_LOGE(TAG, "Signed-manifest verification failed: 0x%x", (unsigned)verr);
                                cJSON_Delete(root);
                                return verr;
                                }
                            cJSON_Delete(root);

                            if (last_err == ESP_OK) {
                                ESP_LOGI(TAG, "Manifest OK: version=%s secure_version=%u url=%s size=%u",
                                         out.version, (unsigned)out.secure_version, out.url, (unsigned)out.size);
                                return ESP_OK;
                            }
                        }
                    }
                }
            }
        }

        if (MANIFEST_MAX_RETRIES > 0 && attempt >= MANIFEST_MAX_RETRIES) {
            return last_err;
        }

        const int backoff = compute_backoff_ms(attempt);
        ESP_LOGW(TAG, "Retrying manifest fetch in %d ms....", backoff);
        vTaskDelay(pdMS_TO_TICKS(backoff));
    }
}

} // namespace ota
