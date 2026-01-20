#include "mqtt_creds.h"

#include <cstring>
#include <cstdlib>

extern "C" {
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_check.h"
}

static const char* TAG = "mqtt_creds";

extern "C" {
// Always embedded (public)
extern const char _binary_cicada_ca_crt_start[] asm("_binary_cicada_ca_crt_start");
extern const char _binary_control_pub_pem_start[] asm("_binary_control_pub_pem_start");

// Only embedded in provisioning build (secret)
#ifdef CONFIG_CICADA_PROVISION_FROM_EMBEDDED
extern const char _binary_device_crt_start[] asm("_binary_device_crt_start");
extern const char _binary_device_crt_end[]   asm("_binary_device_crt_end");
extern const char _binary_device_key_start[] asm("_binary_device_key_start");
extern const char _binary_device_key_end[]   asm("_binary_device_key_end");
#endif
}

namespace {

// NVS namespace + keys
static constexpr const char* NVS_NS      = "mqtt_creds";
static constexpr const char* KEY_CRT_PEM = "client_crt";
static constexpr const char* KEY_KEY_PEM = "client_key";

// Keep loaded creds in RAM for lifetime of MQTT client
static char* s_client_crt = nullptr;
static char* s_client_key = nullptr;

static void free_loaded()
{
    if (s_client_crt) { std::free(s_client_crt); s_client_crt = nullptr; }
    if (s_client_key) { std::free(s_client_key); s_client_key = nullptr; }
}

static esp_err_t nvs_get_blob_alloc(nvs_handle_t h, const char* key, char** out_buf)
{
    size_t len = 0;
    esp_err_t err = nvs_get_blob(h, key, nullptr, &len);
    if (err != ESP_OK) return err;
    if (len == 0) return ESP_ERR_INVALID_SIZE;

    char* p = (char*)std::malloc(len + 1);
    if (!p) return ESP_ERR_NO_MEM;

    err = nvs_get_blob(h, key, p, &len);
    if (err != ESP_OK) {
        std::free(p);
        return err;
    }
    p[len] = '\0'; // ensure null-terminated PEM
    *out_buf = p;
    return ESP_OK;
}

static esp_err_t nvs_set_blob_str(nvs_handle_t h, const char* key, const char* data, size_t len)
{
    // store without requiring trailing null; we add it on read
    return nvs_set_blob(h, key, data, len);
}

static esp_err_t ensure_nvs_ready()
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    return err;
}

} // namespace

namespace mqtt_creds {

const char* ca_pem() { return _binary_cicada_ca_crt_start; }
const char* control_pub_pem() { return _binary_control_pub_pem_start; }

const char* client_crt_pem() { return s_client_crt; }
const char* client_key_pem() { return s_client_key; }

esp_err_t init(bool allow_provision_from_embedded)
{
    free_loaded();

    ESP_RETURN_ON_ERROR(ensure_nvs_ready(), TAG, "nvs init failed");

    nvs_handle_t h = 0;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: 0x%x", (unsigned)err);
        return err;
    }

    // Try load existing creds
    err = nvs_get_blob_alloc(h, KEY_CRT_PEM, &s_client_crt);
    esp_err_t err2 = nvs_get_blob_alloc(h, KEY_KEY_PEM, &s_client_key);

    if (err == ESP_OK && err2 == ESP_OK) {
        ESP_LOGI(TAG, "MQTT creds loaded from NVS");
        nvs_close(h);
        return ESP_OK;
    }

    // Missing creds
    free_loaded();

    if (!allow_provision_from_embedded) {
        ESP_LOGE(TAG, "MQTT creds missing in NVS and provisioning disabled");
        nvs_close(h);
        return ESP_ERR_NOT_FOUND;
    }

#ifndef CONFIG_CICADA_PROVISION_FROM_EMBEDDED
    ESP_LOGE(TAG, "Provisioning requested but firmware was built without embedded device.crt/key");
    nvs_close(h);
    return ESP_ERR_NOT_SUPPORTED;
#else
    // Provision from embedded files (factory/provisioning build)
    const char* crt = _binary_device_crt_start;
    const size_t crt_len = (size_t)(_binary_device_crt_end - _binary_device_crt_start);

    const char* key = _binary_device_key_start;
    const size_t key_len = (size_t)(_binary_device_key_end - _binary_device_key_start);

    ESP_LOGW(TAG, "Provisioning MQTT creds into NVS (one-time)");

    err = nvs_set_blob_str(h, KEY_CRT_PEM, crt, crt_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_set_blob cert failed: 0x%x", (unsigned)err);
        nvs_close(h);
        return err;
    }

    err = nvs_set_blob_str(h, KEY_KEY_PEM, key, key_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_set_blob key failed: 0x%x", (unsigned)err);
        nvs_close(h);
        return err;
    }

    err = nvs_commit(h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_commit failed: 0x%x", (unsigned)err);
        nvs_close(h);
        return err;
    }

    nvs_close(h);

    // Reload into RAM
    ESP_RETURN_ON_ERROR(nvs_open(NVS_NS, NVS_READONLY, &h), TAG, "nvs_open ro failed");
    ESP_RETURN_ON_ERROR(nvs_get_blob_alloc(h, KEY_CRT_PEM, &s_client_crt), TAG, "reload cert failed");
    ESP_RETURN_ON_ERROR(nvs_get_blob_alloc(h, KEY_KEY_PEM, &s_client_key), TAG, "reload key failed");
    nvs_close(h);

    ESP_LOGI(TAG, "MQTT creds provisioned and loaded");
    return ESP_OK;
#endif
}

} // namespace mqtt_creds
