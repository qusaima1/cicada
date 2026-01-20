#pragma once

#include "update_manager.h"   // your interface header renamed to .h
// If your update_manager interface types are in a different header, include that instead.

namespace ota {
    class HttpsOtaTransport : public ITransport {
    public:
        esp_err_t download_and_write(const Manifest& m,
                                     const esp_partition_t* update_partition,
                                     ProgressCb progress_cb) override;
    };
}
