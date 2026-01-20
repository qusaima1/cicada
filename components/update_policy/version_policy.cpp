#include "version_policy.h"

#include <cstring>

extern "C" {
#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_efuse.h"
#include "esp_app_desc.h"
}

namespace ota {

static const char* TAG = "version_policy";

bool VersionPolicy::parse_semver(const char* s, int& maj, int& min, int& pat)
{
    if (!s || !*s) return false;

    // Accept formats like: "1.2.3", "v1.2.3", "1.2", "1", and stop at '-' or '+'
    // Examples: "1.2.3-beta" -> parses as 1.2.3
    if (s[0] == 'v' || s[0] == 'V') s++;

    auto parse_int = [](const char*& p, int& out) -> bool {
        if (*p < '0' || *p > '9') return false;
        int val = 0;
        while (*p >= '0' && *p <= '9') {
            val = (val * 10) + (*p - '0');
            p++;
        }
        out = val;
        return true;
    };

    const char* p = s;
    maj = min = pat = 0;

    if (!parse_int(p, maj)) return false;

    if (*p == '.' ) {
        p++;
        if (!parse_int(p, min)) return false;
    } else {
        // "1"
        min = 0;
        pat = 0;
        return true;
    }

    if (*p == '.' ) {
        p++;
        if (!parse_int(p, pat)) return false;
    } else {
        // "1.2"
        pat = 0;
        return true;
    }

    // If there is suffix like -rc1 or +build, ignore it.
    return true;
}

int VersionPolicy::cmp_semver(int aM, int am, int ap, int bM, int bm, int bp)
{
    if (aM != bM) return (aM < bM) ? -1 : 1;
    if (am != bm) return (am < bm) ? -1 : 1;
    if (ap != bp) return (ap < bp) ? -1 : 1;
    return 0;
}

bool VersionPolicy::allow_update(const Manifest& m, FailReason& out_reason)
{
    out_reason = FailReason::NONE;

    // Read current running app info
    const esp_app_desc_t* app = esp_app_get_description();
    const char* current_ver = app ? app->version : "0.0.0";
    const uint32_t running_sv = app ? (uint32_t)app->secure_version : 0;

    // Read chip anti-rollback secure version (eFuse)
    // This is the authoritative monotonic baseline once anti-rollback is enabled.
    const uint32_t chip_sv = esp_efuse_read_secure_version();

    // ----- Phase 4: secure_version policy gates -----
    // 1) Hard reject: manifest secure_version below chip secure version (downgrade)
    if (m.secure_version < chip_sv) {
        ESP_LOGE(TAG, "Reject: manifest secure_version=%u < chip secure_version=%u",
                 (unsigned)m.secure_version, (unsigned)chip_sv);
        out_reason = FailReason::POLICY_REJECTED;
        return false;
    }

    // 2) Sanity reject: manifest secure_version below the running image secure_version
    // (Should not happen in a sane release process.)
    if (m.secure_version < running_sv) {
        ESP_LOGE(TAG, "Reject: manifest secure_version=%u < running secure_version=%u",
                 (unsigned)m.secure_version, (unsigned)running_sv);
        out_reason = FailReason::POLICY_REJECTED;
        return false;
    }

    // 3) Optional: If you still want a "policy floor" separate from eFuse,
    // keep this check. Otherwise you can delete it.
    // It can be used as a "minimum allowed epoch" in software.
    if (m.secure_version < current_secure_version_) {
        ESP_LOGE(TAG, "Reject: manifest secure_version=%u < policy floor=%u",
                 (unsigned)m.secure_version, (unsigned)current_secure_version_);
        out_reason = FailReason::POLICY_REJECTED;
        return false;
    }
    // -----------------------------------------------

    // Compare semantic versions: manifest.version vs running firmware version
    int curM, curm, curp;
    int manM, manm, manp;

    const bool cur_ok = parse_semver(current_ver, curM, curm, curp);
    const bool man_ok = parse_semver(m.version,   manM, manm, manp);

    if (!cur_ok || !man_ok) {
        // Conservative fallback: if we cannot parse, avoid repeated updates:
        if (std::strcmp(m.version, current_ver) == 0) {
            ESP_LOGI(TAG, "No update (non-semver): manifest version equals current (%s)", current_ver);
            out_reason = FailReason::NO_UPDATE_AVAILABLE;
            return false;
        }

        // If versions differ, allow update only if secure_version increases
        // relative to running image or chip.
        if (m.secure_version > running_sv || m.secure_version > chip_sv) {
            ESP_LOGW(TAG, "Allow update (non-semver) due to secure_version increase (running=%u chip=%u -> manifest=%u)",
                     (unsigned)running_sv, (unsigned)chip_sv, (unsigned)m.secure_version);
            return true;
        }

        ESP_LOGI(TAG, "No update (non-semver). current=%s manifest=%s", current_ver, m.version);
        out_reason = FailReason::NO_UPDATE_AVAILABLE;
        return false;
    }

    const int cmp = cmp_semver(curM, curm, curp, manM, manm, manp);
    if (cmp >= 0) {
        ESP_LOGI(TAG, "No update: current=%s manifest=%s", current_ver, m.version);
        out_reason = FailReason::NO_UPDATE_AVAILABLE;
        return false;
    }

    ESP_LOGI(TAG,
             "Update allowed: current=%s (sv running=%u chip=%u) -> manifest=%s (sv=%u)",
             current_ver, (unsigned)running_sv, (unsigned)chip_sv,
             m.version, (unsigned)m.secure_version);

    return true;
}

} // namespace ota
