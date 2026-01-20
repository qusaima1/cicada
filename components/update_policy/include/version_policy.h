#pragma once

#include "update_manager.h"

namespace ota {

// Compares current running app version vs manifest version.
// Allows update only when manifest version is newer.
// Also rejects if manifest.secure_version < current_secure_version (anti-downgrade gate).
class VersionPolicy : public IPolicy {
public:
    explicit VersionPolicy(uint32_t current_secure_version)
        : current_secure_version_(current_secure_version) {}

    bool allow_update(const Manifest& m, FailReason& out_reason) override;

private:
    uint32_t current_secure_version_;

    static bool parse_semver(const char* s, int& maj, int& min, int& pat);
    static int  cmp_semver(int aM, int am, int ap, int bM, int bm, int bp);
};

} // namespace ota
