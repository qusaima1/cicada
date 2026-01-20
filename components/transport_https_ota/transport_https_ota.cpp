#include "transport_https_ota.h"

#include <cstring>

extern "C" {
#include "esp_log.h"
#include "esp_https_ota.h"
#include "esp_http_client.h"
#include "esp_partition.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"
#include "esp_heap_caps.h"
}

#include "trust_store.h"

namespace ota {

static const char* TAG = "transport_https_ota";

// Retry policy
static constexpr int  OTA_MAX_RETRIES        = 0;       // 0 = retry forever on CONNECT failures
static constexpr int  OTA_HTTP_TIMEOUT_MS    = 15000;   // per attempt
static constexpr int  OTA_BACKOFF_START_MS   = 1000;    // 1s
static constexpr int  OTA_BACKOFF_MAX_MS     = 30000;   // 30s

static bool is_all_zero_sha(const uint8_t sha[32])
{
    for (int i = 0; i < 32; ++i) if (sha[i] != 0) return false;
    return true;
}

static void sha_to_hex(const uint8_t in[32], char out_hex[65])
{
    static const char* hex = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out_hex[i * 2]     = hex[(in[i] >> 4) & 0xF];
        out_hex[i * 2 + 1] = hex[in[i] & 0xF];
    }
    out_hex[64] = '\0';
}

static esp_err_t sha256_partition_range(const esp_partition_t* part, size_t len, uint8_t out_sha[32])
{
    if (!part || len == 0) return ESP_ERR_INVALID_ARG;

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); // 0 => SHA-256

    const size_t chunk = 2048; // smaller chunk reduces RAM pressure; 2048 is fine
    uint8_t* buf = (uint8_t*)heap_caps_malloc(chunk, MALLOC_CAP_8BIT);
    if (!buf) {
        mbedtls_sha256_free(&ctx);
        return ESP_ERR_NO_MEM;
    }

    size_t offset = 0;
    while (offset < len) {
        size_t to_read = (len - offset > chunk) ? chunk : (len - offset);

        esp_err_t err = esp_partition_read(part, offset, buf, to_read);
        if (err != ESP_OK) {
            heap_caps_free(buf);
            mbedtls_sha256_free(&ctx);
            return err;
        }

        mbedtls_sha256_update(&ctx, buf, to_read);
        offset += to_read;
    }

    mbedtls_sha256_finish(&ctx, out_sha);

    heap_caps_free(buf);
    mbedtls_sha256_free(&ctx);
    return ESP_OK;
}

static int compute_backoff_ms(int attempt)
{
    int backoff = OTA_BACKOFF_START_MS;
    for (int i = 1; i < attempt; ++i) {
        if (backoff < OTA_BACKOFF_MAX_MS / 2) backoff *= 2;
        else backoff = OTA_BACKOFF_MAX_MS;
    }
    if (backoff > OTA_BACKOFF_MAX_MS) backoff = OTA_BACKOFF_MAX_MS;
    return backoff;
}

static bool retryable(esp_err_t err)
{
    // Only retry on connectivity-ish failures.
    if (err == ESP_ERR_HTTP_CONNECT) return true;
    if (err == ESP_FAIL) return true;
    return false;
}

esp_err_t HttpsOtaTransport::download_and_write(const Manifest& m,
                                               const esp_partition_t* update_partition,
                                               ProgressCb progress_cb)
{
    // Enforce manifest completeness (phase 1.5: do not accept "unknown")
    if (m.size == 0) {
        ESP_LOGE(TAG, "Manifest size is 0; refusing update in strict mode");
        return ESP_ERR_INVALID_ARG;
    }
    if (is_all_zero_sha(m.sha256)) {
        ESP_LOGE(TAG, "Manifest sha256 missing/zero; refusing update in strict mode");
        return ESP_ERR_INVALID_ARG;
    }
    if (!update_partition) {
        ESP_LOGE(TAG, "update_partition is null");
        return ESP_ERR_INVALID_ARG;
    }

    int attempt = 0;

    while (true) {
        attempt++;

        ESP_LOGW(TAG, "HTTPS OTA attempt %d (url=%s)", attempt, m.url);

        esp_http_client_config_t http_cfg = {};
        http_cfg.url = m.url;
        http_cfg.cert_pem = trust_store::server_cert_pem();
        http_cfg.timeout_ms = OTA_HTTP_TIMEOUT_MS;

        esp_https_ota_config_t ota_cfg = {};
        ota_cfg.http_config = &http_cfg;

        esp_https_ota_handle_t ota_handle = nullptr;

        esp_err_t err = esp_https_ota_begin(&ota_cfg, &ota_handle);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_https_ota_begin failed: %s (0x%x)", esp_err_to_name(err), (unsigned)err);
        } else {
            // Download + write
            while (true) {
                err = esp_https_ota_perform(ota_handle);
                if (err == ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
                    int read = esp_https_ota_get_image_len_read(ota_handle);
                    int total = esp_https_ota_get_image_size(ota_handle); // can be -1
                    if (total > 0 && progress_cb) {
                        uint8_t pct = (read >= total) ? 100 : (uint8_t)((read * 100) / total);
                        progress_cb(pct);
                    }
                    continue;
                }
                break;
            }

            // Capture bytes read before finish (handle may be freed in finish)
            const int bytes_read = esp_https_ota_get_image_len_read(ota_handle);

            if (err == ESP_OK) {
                err = esp_https_ota_finish(ota_handle);
                if (err == ESP_OK) {
                    // 1) Size check
                    if ((uint32_t)bytes_read != m.size) {
                        ESP_LOGE(TAG, "Size mismatch: downloaded=%d manifest=%u", bytes_read, (unsigned)m.size);
                        return ESP_ERR_INVALID_RESPONSE; // non-retryable
                    }

                    // 2) SHA-256 check over the written bytes in the update partition
                    uint8_t sha_calc[32] = {0};
                    err = sha256_partition_range(update_partition, m.size, sha_calc);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "SHA compute failed: %s (0x%x)", esp_err_to_name(err), (unsigned)err);
                        return err; // likely non-retryable
                    }

                    if (std::memcmp(sha_calc, m.sha256, 32) != 0) {
                        char a[65], b[65];
                        sha_to_hex(sha_calc, a);
                        sha_to_hex(m.sha256, b);
                        ESP_LOGE(TAG, "SHA mismatch!\n  calc=%s\n  mani=%s", a, b);
                        return ESP_ERR_INVALID_RESPONSE; // non-retryable
                    }

                    if (progress_cb) progress_cb(100);
                    ESP_LOGI(TAG, "HTTPS OTA OK (size+sha256 verified)");
                    return ESP_OK;
                }
                ESP_LOGE(TAG, "esp_https_ota_finish failed: %s (0x%x)", esp_err_to_name(err), (unsigned)err);
            } else {
                ESP_LOGE(TAG, "esp_https_ota_perform failed: %s (0x%x)", esp_err_to_name(err), (unsigned)err);
            }

            esp_https_ota_abort(ota_handle);
        }

        // Retry policy
        if (OTA_MAX_RETRIES > 0 && attempt >= OTA_MAX_RETRIES) {
            ESP_LOGE(TAG, "Reached max retries (%d). Giving up.", OTA_MAX_RETRIES);
            return ESP_FAIL;
        }

        if (!retryable(err)) {
            ESP_LOGE(TAG, "Non-retryable error. Giving up.");
            return err;
        }

        const int backoff = compute_backoff_ms(attempt);
        ESP_LOGW(TAG, "Retrying in %d ms...", backoff);
        vTaskDelay(pdMS_TO_TICKS(backoff));
    }
}

} // namespace ota
