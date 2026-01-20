# Cicada — Security-First IoT Firmware Platform (ESP32 / ESP-IDF)

Cicada is a security-focused ESP32 firmware platform layered trust, cryptographic governance, and verifiable security behaviors. The project demonstrates an end-to-end secure lifecycle for IoT devices:

1) **Secure OTA updates** (authorized + integrity-verified + rollback-safe)  
2) **Hardware hardening** (Secure Boot v2, Flash Encryption, Anti-rollback)  
3) **Secure online operation** (mTLS MQTT + broker ACL isolation + signed commands + anti-replay)

This repo is designed as a production-aligned reference implementation: it prioritizes practical security controls and test evidence over “demo crypto.”

---

## Highlights

### Secure OTA (Update Plane)
- A/B OTA partitions + rollback + post-boot confirmation (self-test + mark valid)
- **Signed manifest** (Root-authorized release cert → Release-signed manifest)
- **SHA-256 + size enforcement** on-device (rejects tampered firmware or metadata)
- Retry/backoff for transient network issues

### Hardware Trust (Platform Hardening)
- **Secure Boot v2 (RSA-PSS)** fused (eFuses) → only signed bootloader/app run
- **Flash Encryption** enabled → firmware/secrets protected at rest
- **Encrypted NVS** (requires `nvs_keys` partition)
- **Anti-rollback**: secure version gating to block downgrade to vulnerable firmware
- OTA-only partition layout compatible with anti-rollback (no factory/test partitions)

### Connected Security (Control Plane)
- Outbound-only **MQTT over TLS (mTLS)** with per-device X.509 certs
- Mosquitto broker **requires client certs** + uses CN as identity + **ACL patterns**
- **Message-level signed commands (ECDSA)** + monotonic anti-replay counter stored in NVS
- Provisioning vs Release workflow: **release build ships with 0 embedded device private keys**

---
## Scaling to Real Privacy-Critical IoT Systems
Cicada’s architecture scales cleanly to:
-Fleet provisioning and certificate rotation
-Audit-grade release governance (signed manifests as artifacts)
-Key revocation (device cert revocation and command key rotation)
-Cloud brokers (EMQX/HiveMQ/AWS IoT) using same mTLS + per-device policies
-Privacy-by-design data minimization and least-privilege topic namespaces
### Core principle: authorization and integrity are cryptographic and verifiable; connectivity is authenticated; and secrets are protected at rest by hardware mechanisms.
