#pragma once

#include <cstdint>
#include <functional>

extern "C" {
#include "esp_err.h"
#include "esp_ota_ops.h"
}

namespace ota {

enum class State : uint8_t {
    IDLE = 0,
    CHECKING_MANIFEST,
    APPLYING_UPDATE,
    SETTING_BOOT_PARTITION,
    REBOOTING_TO_VERIFY,
    POST_BOOT_SELFTEST,
    CONFIRMING_IMAGE,
    FAILED
};

enum class Trigger : uint8_t {
    CHECK_ONLY = 0,
    DOWNLOAD_AND_APPLY
};

enum class FailReason : uint16_t {
    NONE = 0,
    MANIFEST_FETCH_FAILED,
    NO_UPDATE_AVAILABLE,
    POLICY_REJECTED,
    TRANSPORT_FAILED,
    OTA_NO_UPDATE_PARTITION,
    OTA_SET_BOOT_FAILED,
    SELFTEST_FAILED,
    OTA_MARK_VALID_FAILED,
};

struct Manifest {
    // Minimal now; we will expand later.
    char version[32] = {0};
    uint32_t secure_version = 0;
    char url[256] = {0};
    uint8_t sha256[32] = {0};
    uint32_t size = 0;
};

struct Status {
    State state = State::IDLE;
    FailReason reason = FailReason::NONE;
    esp_err_t last_err = ESP_OK;
    uint8_t progress_pct = 0;
};

class IManifestSource {
public:
    virtual ~IManifestSource() = default;
    virtual esp_err_t fetch(Manifest& out) = 0;
};

class IPolicy {
public:
    virtual ~IPolicy() = default;
    virtual bool allow_update(const Manifest& m, FailReason& out_reason) = 0;
};

class ITransport {
public:
    using ProgressCb = std::function<void(uint8_t pct)>;
    virtual ~ITransport() = default;

    // Must download the image and write it to the provided update partition.
    // Must NOT reboot. update_manager controls reboot/boot selection.
    virtual esp_err_t download_and_write(const Manifest& m,
                                         const esp_partition_t* update_partition,
                                         ProgressCb progress_cb) = 0;
};

class UpdateManager {
public:
    using SelfTestFn = std::function<bool(void)>; // return true => OK, false => FAIL

    struct Config {
        IManifestSource* manifest = nullptr;
        IPolicy* policy = nullptr;
        ITransport* transport = nullptr;

        // Called after reboot when the running image is in PENDING_VERIFY state.
        // If it returns false, update_manager triggers rollback.
        SelfTestFn self_test = nullptr;

        // Task parameters
        uint32_t task_stack_words = 4096;
        uint32_t task_priority = 5;
        uint32_t queue_len = 8;
    };

    explicit UpdateManager(const Config& cfg);
    ~UpdateManager();

    // Start background task
    esp_err_t start();

    // Call this early at boot (in app_main) to handle PENDING_VERIFY logic.
    esp_err_t handle_boot_verification();

    // Trigger an update workflow
    esp_err_t trigger(Trigger t);

    // Get current status (thread-safe snapshot)
    Status get_status() const;

private:
    struct Event {
        Trigger trig;
    };

    static void task_entry(void* arg);
    void task_loop();
    void set_state(State s);
    void fail(FailReason r, esp_err_t e);

    esp_err_t run_check_only();
    esp_err_t run_download_and_apply();

    Config cfg_;
    mutable Status status_;

    void* queue_ = nullptr; // FreeRTOS QueueHandle_t (kept void* to avoid including freertos headers here)
    void* task_ = nullptr;  // TaskHandle_t
};

} // namespace ota
