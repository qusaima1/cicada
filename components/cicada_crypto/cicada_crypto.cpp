#include "cicada_crypto.h"

#include <cstring>
#include <string>

extern "C" {
#include "esp_log.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
}

static const char* TAG = "cicada_crypto";
static const char* ALG = "ECDSA_P256_SHA256";

extern "C" {
extern const char _binary_root_pub_pem_start[] asm("_binary_root_pub_pem_start");
extern const char _binary_root_pub_pem_end[]   asm("_binary_root_pub_pem_end");
}

static esp_err_t b64_decode(const char* s, uint8_t* out, size_t out_cap, size_t* out_len)
{
    if (!s) return ESP_ERR_INVALID_ARG;
    size_t olen = 0;
    int rc = mbedtls_base64_decode(out, out_cap, &olen,
                                  reinterpret_cast<const unsigned char*>(s),
                                  std::strlen(s));
    if (rc != 0) return ESP_ERR_INVALID_RESPONSE;
    *out_len = olen;
    return ESP_OK;
}

static void sha256_bytes(const uint8_t* data, size_t len, uint8_t out32[32])
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, data, len);
    mbedtls_sha256_finish(&ctx, out32);
    mbedtls_sha256_free(&ctx);
}

static std::string cert_payload_string(const char* key_id,
                                       const char* channel,
                                       const char* not_before,
                                       const char* not_after,
                                       const char* pubkey_der_b64)
{
    std::string s;
    s.reserve(512);
    s += "CICADA-CERT-v1\n";
    s += "key_id="; s += key_id; s += "\n";
    s += "alg="; s += ALG; s += "\n";
    s += "channel="; s += channel; s += "\n";
    s += "not_before="; s += not_before; s += "\n";
    s += "not_after="; s += not_after; s += "\n";
    s += "pubkey_der_b64="; s += pubkey_der_b64; s += "\n";
    // IMPORTANT: exactly ONE trailing newline (no extra blank line)
    return s;
}

static std::string manifest_payload_string(const ota::Manifest& m,
                                           const char* channel,
                                           const char* key_id)
{
    std::string s;
    s.reserve(512);
    s += "CICADA-MANIFEST-v1\n";
    s += "version="; s += m.version; s += "\n";
    s += "secure_version="; s += std::to_string(m.secure_version); s += "\n";
    s += "url="; s += m.url; s += "\n";
    s += "size="; s += std::to_string(m.size); s += "\n";

    static const char* hex = "0123456789abcdef";
    char shahex[65];
    for (int i = 0; i < 32; ++i) {
        shahex[i*2]   = hex[(m.sha256[i] >> 4) & 0xF];
        shahex[i*2+1] = hex[m.sha256[i] & 0xF];
    }
    shahex[64] = '\0';

    s += "sha256="; s += shahex; s += "\n";
    s += "channel="; s += channel; s += "\n";
    s += "key_id="; s += key_id; s += "\n";
    // IMPORTANT: exactly ONE trailing newline
    return s;
}


namespace cicada {

esp_err_t verify_signed_manifest(const ota::Manifest& m, const cJSON* cicada_obj)
{
    if (!cicada_obj || !cJSON_IsObject(cicada_obj)) return ESP_ERR_INVALID_RESPONSE;

    const cJSON* j_channel = cJSON_GetObjectItemCaseSensitive(cicada_obj, "channel");
    const cJSON* j_cert    = cJSON_GetObjectItemCaseSensitive(cicada_obj, "release_cert");
    const cJSON* j_msig    = cJSON_GetObjectItemCaseSensitive(cicada_obj, "manifest_sig_b64");

    if (!cJSON_IsString(j_channel) || !j_channel->valuestring ||
        !cJSON_IsObject(j_cert) ||
        !cJSON_IsString(j_msig) || !j_msig->valuestring) {
        ESP_LOGE(TAG, "Missing cicada fields");
        return ESP_ERR_INVALID_RESPONSE;
    }

    const char* channel = j_channel->valuestring;

    const cJSON* j_key_id   = cJSON_GetObjectItemCaseSensitive(j_cert, "key_id");
    const cJSON* j_alg      = cJSON_GetObjectItemCaseSensitive(j_cert, "alg");
    const cJSON* j_cchan    = cJSON_GetObjectItemCaseSensitive(j_cert, "channel");
    const cJSON* j_nb       = cJSON_GetObjectItemCaseSensitive(j_cert, "not_before");
    const cJSON* j_na       = cJSON_GetObjectItemCaseSensitive(j_cert, "not_after");
    const cJSON* j_pub_b64  = cJSON_GetObjectItemCaseSensitive(j_cert, "pubkey_der_b64");
    const cJSON* j_csig_b64 = cJSON_GetObjectItemCaseSensitive(j_cert, "sig_b64");

    if (!cJSON_IsString(j_key_id) || !j_key_id->valuestring ||
        !cJSON_IsString(j_alg)    || !j_alg->valuestring ||
        !cJSON_IsString(j_cchan)  || !j_cchan->valuestring ||
        !cJSON_IsString(j_nb)     || !j_nb->valuestring ||
        !cJSON_IsString(j_na)     || !j_na->valuestring ||
        !cJSON_IsString(j_pub_b64)|| !j_pub_b64->valuestring ||
        !cJSON_IsString(j_csig_b64)|| !j_csig_b64->valuestring) {
        ESP_LOGE(TAG, "Invalid release_cert fields");
        return ESP_ERR_INVALID_RESPONSE;
    }

    const char* key_id = j_key_id->valuestring;

    if (std::strcmp(j_alg->valuestring, ALG) != 0) {
        ESP_LOGE(TAG, "Unsupported alg: %s", j_alg->valuestring);
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (std::strcmp(j_cchan->valuestring, channel) != 0) {
        ESP_LOGE(TAG, "Channel mismatch (cert vs cicada)");
        return ESP_ERR_INVALID_RESPONSE;
    }

    // 1) Parse Root public key (PEM)
    mbedtls_pk_context root_pk;
    mbedtls_pk_init(&root_pk);

    const size_t root_len = (size_t)(_binary_root_pub_pem_end - _binary_root_pub_pem_start);
    int rc = mbedtls_pk_parse_public_key(&root_pk,
                                        reinterpret_cast<const unsigned char*>(_binary_root_pub_pem_start),
                                        root_len);
    if (rc != 0) {
        ESP_LOGE(TAG, "Root pub parse failed (rc=%d)", rc);
        mbedtls_pk_free(&root_pk);
        return ESP_FAIL;
    }

    // 2) Verify release certificate signature (Root over cert payload)
    std::string cert_payload = cert_payload_string(
        key_id, channel, j_nb->valuestring, j_na->valuestring, j_pub_b64->valuestring);

    uint8_t cert_hash[32];
    sha256_bytes(reinterpret_cast<const uint8_t*>(cert_payload.data()), cert_payload.size(), cert_hash);

    uint8_t cert_sig[256];
    size_t cert_sig_len = 0;
    esp_err_t err = b64_decode(j_csig_b64->valuestring, cert_sig, sizeof(cert_sig), &cert_sig_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Cert sig b64 decode failed");
        mbedtls_pk_free(&root_pk);
        return err;
    }

    rc = mbedtls_pk_verify(&root_pk, MBEDTLS_MD_SHA256, cert_hash, 0, cert_sig, cert_sig_len);
    mbedtls_pk_free(&root_pk);

    if (rc != 0) {
        ESP_LOGE(TAG, "Release cert signature INVALID (rc=%d)", rc);
        return ESP_ERR_INVALID_RESPONSE;
    }

    // 3) Parse release public key DER from cert
    uint8_t rel_der[1024];
    size_t rel_der_len = 0;
    err = b64_decode(j_pub_b64->valuestring, rel_der, sizeof(rel_der), &rel_der_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Release pubkey b64 decode failed");
        return err;
    }

    mbedtls_pk_context rel_pk;
    mbedtls_pk_init(&rel_pk);
    rc = mbedtls_pk_parse_public_key(&rel_pk, rel_der, rel_der_len);
    if (rc != 0) {
        ESP_LOGE(TAG, "Release pub parse failed (rc=%d)", rc);
        mbedtls_pk_free(&rel_pk);
        return ESP_FAIL;
    }

    // 4) Verify manifest signature (Release over manifest payload)
    std::string mani_payload = manifest_payload_string(m, channel, key_id);

    uint8_t mani_hash[32];
    sha256_bytes(reinterpret_cast<const uint8_t*>(mani_payload.data()), mani_payload.size(), mani_hash);

    uint8_t mani_sig[256];
    size_t mani_sig_len = 0;
    err = b64_decode(j_msig->valuestring, mani_sig, sizeof(mani_sig), &mani_sig_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Manifest sig b64 decode failed");
        mbedtls_pk_free(&rel_pk);
        return err;
    }

    rc = mbedtls_pk_verify(&rel_pk, MBEDTLS_MD_SHA256, mani_hash, 0, mani_sig, mani_sig_len);
    mbedtls_pk_free(&rel_pk);

    if (rc != 0) {
        ESP_LOGE(TAG, "Manifest signature INVALID (rc=%d)", rc);
        return ESP_ERR_INVALID_RESPONSE;
    }

    ESP_LOGI(TAG, "Cicada signatures OK (cert + manifest)");
    return ESP_OK;
}

} // namespace cicada
