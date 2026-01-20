#include "update_manager.h"

extern "C" {
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_ota_ops.h"
}

namespace ota {

static const char* TAG = "update_manager";

UpdateManager::UpdateManager(const Config& cfg) : cfg_(cfg) {
    status_ = {};
}

UpdateManager::~UpdateManager() {
    if (task_) {
        vTaskDelete(static_cast<TaskHandle_t>(task_));
        task_ = nullptr;
    }
    if (queue_) {
        vQueueDelete(static_cast<QueueHandle_t>(queue_));
        queue_ = nullptr;
    }
}

esp_err_t UpdateManager::start() {
    if (!cfg_.manifest || !cfg_.policy || !cfg_.transport) {
        ESP_LOGE(TAG, "Missing dependencies (manifest/policy/transport)");
        return ESP_ERR_INVALID_ARG;
    }
    if (!cfg_.self_test) {
        ESP_LOGW(TAG, "self_test not set; boot verification will be unsafe");
    }

    queue_ = xQueueCreate(cfg_.queue_len, sizeof(Event));
    if (!queue_) {
        ESP_LOGE(TAG, "Failed to create queue");
        return ESP_ERR_NO_MEM;
    }

    BaseType_t ok = xTaskCreate(&UpdateManager::task_entry,
                               "update_manager",
                               cfg_.task_stack_words,
                               this,
                               cfg_.task_priority,
                               reinterpret_cast<TaskHandle_t*>(&task_));
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "Failed to create task");
        vQueueDelete(static_cast<QueueHandle_t>(queue_));
        queue_ = nullptr;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "UpdateManager started");
    return ESP_OK;
}

esp_err_t UpdateManager::trigger(Trigger t) {
    if (!queue_) return ESP_ERR_INVALID_STATE;

    Event ev{t};
    if (xQueueSend(static_cast<QueueHandle_t>(queue_), &ev, 0) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

Status UpdateManager::get_status() const {
    return status_;
}

void UpdateManager::set_state(State s) {
    status_.state = s;
    // keep reason/last_err unless transitioning out of FAILED
    ESP_LOGI(TAG, "State -> %u", static_cast<unsigned>(s));
}

void UpdateManager::fail(FailReason r, esp_err_t e) {
    status_.state = State::FAILED;
    status_.reason = r;
    status_.last_err = e;
    ESP_LOGE(TAG, "FAILED reason=%u err=0x%x", static_cast<unsigned>(r), (unsigned)e);
}

void UpdateManager::task_entry(void* arg) {
    static_cast<UpdateManager*>(arg)->task_loop();
}

void UpdateManager::task_loop() {
    Event ev{};
    for (;;) {
        if (xQueueReceive(static_cast<QueueHandle_t>(queue_), &ev, portMAX_DELAY) == pdTRUE) {
            status_.reason = FailReason::NONE;
            status_.last_err = ESP_OK;
            status_.progress_pct = 0;

            esp_err_t err = ESP_OK;
            if (ev.trig == Trigger::CHECK_ONLY) {
                err = run_check_only();
            } else {
                err = run_download_and_apply();
            }

            if (err == ESP_OK) {
                set_state(State::IDLE);
            } else {
                // fail() already logged in most cases; ensure state is FAILED if not set
                if (status_.state != State::FAILED) {
                    fail(FailReason::TRANSPORT_FAILED, err);
                }
            }
        }
    }
}

esp_err_t UpdateManager::run_check_only() {
    set_state(State::CHECKING_MANIFEST);

    Manifest m{};
    esp_err_t err = cfg_.manifest->fetch(m);
    if (err != ESP_OK) {
        fail(FailReason::MANIFEST_FETCH_FAILED, err);
        return err;
    }

    FailReason pr = FailReason::NONE;
if (!cfg_.policy->allow_update(m, pr)) {
    if (pr == FailReason::NO_UPDATE_AVAILABLE) {
        ESP_LOGI(TAG, "No update available (policy)");
        return ESP_OK; // <-- IMPORTANT: not a failure
    }
    fail(pr == FailReason::NONE ? FailReason::POLICY_REJECTED : pr, ESP_FAIL);
    return ESP_FAIL;
}

    ESP_LOGI(TAG, "Update available (check-only). version=%s secure_version=%u url=%s",
             m.version, (unsigned)m.secure_version, m.url);
    return ESP_OK;
}

esp_err_t UpdateManager::run_download_and_apply() {
    set_state(State::CHECKING_MANIFEST);

    Manifest m{};
    esp_err_t err = cfg_.manifest->fetch(m);
    if (err != ESP_OK) {
        fail(FailReason::MANIFEST_FETCH_FAILED, err);
        return err;
    }

    FailReason pr = FailReason::NONE;
if (!cfg_.policy->allow_update(m, pr)) {
    if (pr == FailReason::NO_UPDATE_AVAILABLE) {
        ESP_LOGI(TAG, "No update available (policy)");
        return ESP_OK; // <-- IMPORTANT: not a failure
    }
    fail(pr == FailReason::NONE ? FailReason::POLICY_REJECTED : pr, ESP_FAIL);
    return ESP_FAIL;
}

    const esp_partition_t* update_part = esp_ota_get_next_update_partition(nullptr);
    if (!update_part) {
        fail(FailReason::OTA_NO_UPDATE_PARTITION, ESP_ERR_NOT_FOUND);
        return ESP_ERR_NOT_FOUND;
    }

    set_state(State::APPLYING_UPDATE);
    err = cfg_.transport->download_and_write(
        m,
        update_part,
        [this](uint8_t pct) {
            status_.progress_pct = pct;
            ESP_LOGI(TAG, "OTA progress: %u%%", (unsigned)pct);
        });

    if (err != ESP_OK) {
        fail(FailReason::TRANSPORT_FAILED, err);
        return err;
    }

    set_state(State::SETTING_BOOT_PARTITION);
    err = esp_ota_set_boot_partition(update_part);
    if (err != ESP_OK) {
        fail(FailReason::OTA_SET_BOOT_FAILED, err);
        return err;
    }

    set_state(State::REBOOTING_TO_VERIFY);
    ESP_LOGW(TAG, "Rebooting into new image for verification...");
    esp_restart();

    // not reached
    return ESP_OK;
}

esp_err_t UpdateManager::handle_boot_verification() {
    const esp_partition_t* running = esp_ota_get_running_partition();
    if (!running) return ESP_ERR_NOT_FOUND;
    // If running from factory, OTA image state is typically not tracked.
    // Pending-verify/rollback becomes relevant once you boot from ota_0/ota_1.
    if (running->type == ESP_PARTITION_TYPE_APP &&
    running->subtype == ESP_PARTITION_SUBTYPE_APP_FACTORY) {
    ESP_LOGI(TAG, "Running from factory partition; OTA verify state not applicable yet");
    return ESP_OK;
}

    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    esp_err_t err = esp_ota_get_state_partition(running, &state);
    if (err == ESP_ERR_NOT_SUPPORTED) {
    ESP_LOGI(TAG, "OTA image state not supported in current boot context");
    return ESP_OK;
}
    if (err != ESP_OK) {
    ESP_LOGW(TAG, "esp_ota_get_state_partition failed: 0x%x", (unsigned)err);
    return err;
}

    // If rollback is enabled, newly-booted images can be in PENDING_VERIFY.
    if (state != ESP_OTA_IMG_PENDING_VERIFY) {
        ESP_LOGI(TAG, "Boot state: not pending verify (state=%d)", (int)state);
        return ESP_OK;
    }

    set_state(State::POST_BOOT_SELFTEST);
    bool ok = true;
    if (cfg_.self_test) {
        ok = cfg_.self_test();
    } else {
        // If no self-test is provided, do NOT auto-confirm in a serious project.
        // For now, treat as failure to avoid locking in a potentially bad image.
        ok = false;
        ESP_LOGE(TAG, "No self_test provided; refusing to confirm new image");
    }

    if (ok) {
        set_state(State::CONFIRMING_IMAGE);
        err = esp_ota_mark_app_valid_cancel_rollback();
        if (err != ESP_OK) {
            fail(FailReason::OTA_MARK_VALID_FAILED, err);
            return err;
        }
        ESP_LOGI(TAG, "New image confirmed; rollback cancelled");
        return ESP_OK;
    } else {
        fail(FailReason::SELFTEST_FAILED, ESP_FAIL);
        ESP_LOGE(TAG, "Self-test failed; triggering rollback...");
        // This function triggers rollback + reboot (when rollback is enabled).
        err = esp_ota_mark_app_invalid_rollback_and_reboot();
        // If rollback isn't enabled, it may return an error; still reboot to avoid staying in bad state.
        ESP_LOGW(TAG, "Rollback function returned: 0x%x; rebooting anyway", (unsigned)err);
        esp_restart();
        return err;
    }
}

} // namespace ota
