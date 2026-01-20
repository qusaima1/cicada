#include "wifi_sta.h"
#include "update_manager.h"
#include "transport_https_ota.h"
#include "version_policy.h"
#include "manifest_client.h"
#include "cicada_cmd.h"
#include "cicada_mqtt.h"
#include "mqtt_creds.h"

extern "C" {
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_app_desc.h"
#include "esp_ota_ops.h"
}

static const char* TAG = "APP";

extern "C" void app_main(void)
{
    ESP_LOGI(TAG, "app_main entered");
    const esp_app_desc_t* app = esp_app_get_description();
    ESP_LOGI(TAG, "Running firmware version: %s", app ? app->version : "unknown");

    const esp_partition_t* rp = esp_ota_get_running_partition();
    if (rp) {
    ESP_LOGI(TAG, "Running partition: label=%s offset=0x%lx subtype=0x%x",
             rp->label, (unsigned long)rp->address, (unsigned)rp->subtype);
}
    wifi_sta_start_and_wait();

    // 1) Load/provision MQTT creds FIRST (so pointers are valid)
    ESP_ERROR_CHECK(mqtt_creds::init(false));   // provisioning build
    // for release build later: ESP_ERROR_CHECK(mqtt_creds::init(false));
    ESP_LOGI(TAG, "MQTT CRT len=%u KEY len=%u",
         mqtt_creds::client_crt_pem() ? (unsigned)strlen(mqtt_creds::client_crt_pem()) : 0,
         mqtt_creds::client_key_pem() ? (unsigned)strlen(mqtt_creds::client_key_pem()) : 0);

    // 2) Init command security (replay counter)
    ESP_ERROR_CHECK(cicada_cmd::init());

    // 3) Start MQTT after creds are available
    cicada_mqtt_start("cicada-2805a56f5ab4");

    static ota::ManifestHttpsClient manifest("https://192.168.1.151:8443/manifest.json");

    // Policy: only update if manifest.version is newer than running firmware version.
    // The "current_secure_version" is a project-level anti-downgrade gate for now.
    static ota::VersionPolicy policy(/*current_secure_version=*/2);

    static ota::HttpsOtaTransport transport;

    ota::UpdateManager::Config cfg;
    cfg.task_stack_words = 8192; // 8192 words = 32 KB on ESP32
    cfg.manifest = &manifest;
    cfg.policy = &policy;
    cfg.transport = &transport;
    cfg.self_test = []() -> bool {
        ESP_LOGI(TAG, "Self-test: OK");
        return true;
    };

    static ota::UpdateManager um(cfg);

    // Boot verification becomes relevant after first OTA boot into ota_0/ota_1
    um.handle_boot_verification();

    ESP_ERROR_CHECK(um.start());

    // Safe now: policy will return "no update available" when version is not newer
    ESP_ERROR_CHECK(um.trigger(ota::Trigger::DOWNLOAD_AND_APPLY));

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
