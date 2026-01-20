#include "cicada_cmd.h"

#include <cstring>
#include <string>

extern "C" {
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "cJSON.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
}

#include "mqtt_creds.h"

static const char* TAG = "cicada_cmd";
static nvs_handle_t s_nvs = 0;

static uint64_t nvs_get_u64(const char* key, uint64_t defv)
{
    uint64_t v = 0;
    esp_err_t e = nvs_get_u64(s_nvs, key, &v);
    return (e == ESP_OK) ? v : defv;
}

static void nvs_set_u64(const char* key, uint64_t v)
{
    ESP_ERROR_CHECK(nvs_set_u64(s_nvs, key, v));
    ESP_ERROR_CHECK(nvs_commit(s_nvs));
}

static std::string canonical(const char* device_id, uint64_t ctr, const char* cmd, const char* args_json)
{
    std::string s;
    s.reserve(256 + (args_json ? std::strlen(args_json) : 0));
    s += "CICADA-CMD-v1\n";
    s += "device_id="; s += device_id; s += "\n";
    s += "ctr="; s += std::to_string((unsigned long long)ctr); s += "\n";
    s += "cmd="; s += cmd; s += "\n";
    s += "args_json="; s += (args_json ? args_json : "{}"); s += "\n";
    return s;
}

static bool verify_sig_p256_der_b64(const char* pub_pem, const uint8_t* msg, size_t msg_len, const char* sig_b64)
{
    // Hash message
    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, msg, msg_len);
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    // Decode sig
    uint8_t sig[256];
    size_t sig_len = 0;
    if (mbedtls_base64_decode(sig, sizeof(sig), &sig_len,
                              (const unsigned char*)sig_b64, std::strlen(sig_b64)) != 0) {
        ESP_LOGE(TAG, "sig base64 decode failed");
        return false;
    }

    // Parse pubkey PEM
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_parse_public_key(&pk, (const unsigned char*)pub_pem, std::strlen(pub_pem) + 1) != 0) {
        ESP_LOGE(TAG, "pubkey parse failed");
        mbedtls_pk_free(&pk);
        return false;
    }

    int rc = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, sig, sig_len);
    mbedtls_pk_free(&pk);

    return rc == 0;
}

esp_err_t cicada_cmd::init()
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }
    ESP_ERROR_CHECK(nvs_open("cicada_cmd", NVS_READWRITE, &s_nvs));
    return ESP_OK;
}

bool cicada_cmd::verify_and_update_counter(const char* local_device_id, const char* json,
                                           char* out_cmd, size_t out_cmd_sz,
                                           char* out_args_json, size_t out_args_sz)
{
    cJSON* root = cJSON_Parse(json);
    if (!root) return false;

    const cJSON* j_dev = cJSON_GetObjectItemCaseSensitive(root, "device_id");
    const cJSON* j_ctr = cJSON_GetObjectItemCaseSensitive(root, "ctr");
    const cJSON* j_cmd = cJSON_GetObjectItemCaseSensitive(root, "cmd");
    const cJSON* j_args= cJSON_GetObjectItemCaseSensitive(root, "args_json");
    const cJSON* j_sig = cJSON_GetObjectItemCaseSensitive(root, "sig_b64");

    if (!cJSON_IsString(j_dev) || !cJSON_IsNumber(j_ctr) || !cJSON_IsString(j_cmd) ||
        !cJSON_IsString(j_args) || !cJSON_IsString(j_sig)) {
        cJSON_Delete(root);
        return false;
    }

    const char* dev = j_dev->valuestring;
    uint64_t ctr = (uint64_t)j_ctr->valuedouble;

    // Device binding
    if (std::strcmp(dev, local_device_id) != 0) {
        ESP_LOGW(TAG, "Device ID mismatch");
        cJSON_Delete(root);
        return false;
    }

    // Anti-replay counter
    uint64_t last = nvs_get_u64("last_ctr", 0);
    if (ctr <= last) {
        ESP_LOGW(TAG, "Replay rejected: ctr=%llu last=%llu", (unsigned long long)ctr, (unsigned long long)last);
        cJSON_Delete(root);
        return false;
    }

    // Signature verification
    std::string canon = canonical(dev, ctr, j_cmd->valuestring, j_args->valuestring);
    if (!verify_sig_p256_der_b64(mqtt_creds::control_pub_pem(),
                                 (const uint8_t*)canon.data(), canon.size(),
                                 j_sig->valuestring)) {
        ESP_LOGW(TAG, "Signature invalid");
        cJSON_Delete(root);
        return false;
    }

    // Passed: update replay counter and return command data
    nvs_set_u64("last_ctr", ctr);

    std::snprintf(out_cmd, out_cmd_sz, "%s", j_cmd->valuestring);
    std::snprintf(out_args_json, out_args_sz, "%s", j_args->valuestring);

    cJSON_Delete(root);
    return true;
}
