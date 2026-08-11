#ifndef M4_CREDS_H
#define M4_CREDS_H
/*
 * Provisioned credentials for the Cortex-M4 end-to-end handshake firmware.
 *
 * The values used for the measurements reported in the paper are deployment
 * test credentials (client ML-KEM static secret key, gateway ML-DSA public
 * key, and the per-device anchor). They are NOT published here. To rebuild
 * and rerun the end-to-end experiment you must provision your own values,
 * consistent with the server-side provisioning files used in
 * `network/provision_materials.py` (client static keypair, server signature
 * keypair, and the shared 32-byte anchor). The firmware expects:
 *   - M4_CLIENT_STATIC_SK[1632]: ML-KEM-512 secret key of the enrolled client
 *   - M4_SERVER_SIG_PK[1312]:   ML-DSA-44 public key of the gateway
 *   - M4_ANCHOR[32]:            shared per-device anchor (HKDF salt)
 * Replace the zero-filled arrays below with your provisioned values.
 */
#include <stdint.h>
static const uint8_t M4_CLIENT_STATIC_SK[1632] = {0};
static const uint8_t M4_SERVER_SIG_PK[1312] = {0};
static const uint8_t M4_ANCHOR[32] = {0};
#endif
