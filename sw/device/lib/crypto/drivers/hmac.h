// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef OPENTITAN_SW_DEVICE_LIB_CRYPTO_DRIVERS_HMAC_H_
#define OPENTITAN_SW_DEVICE_LIB_CRYPTO_DRIVERS_HMAC_H_

#include <stddef.h>
#include <stdint.h>

#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/base/hardened.h"
#include "sw/device/lib/crypto/impl/status.h"


#include "hmac_regs.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
  /* Number of bits in an HMAC or SHA-256 digest. */
  kHmacDigestNumBits = 256,
  /* Number of bytes in an HMAC or SHA-256 digest. */
  kHmacDigestNumBytes = kHmacDigestNumBits / 8,
  /* Number of words in an HMAC or SHA-256 digest. */
  kHmacDigestNumWords = kHmacDigestNumBytes / sizeof(uint32_t),
  /* Number of bits in an HMAC key. */
  kHmacKeyNumBits = 256,
  /* Number of bytes in an HMAC key. */
  kHmacKeyNumBytes = kHmacKeyNumBits / 8,
  /* Number of words in an HMAC key. */
  kHmacKeyNumWords = kHmacKeyNumBytes / sizeof(uint32_t),

  /* Number of bits for maximum key size supported by HW natively. */
  kHmacMaxKeyBits = 1024,
  /* Number of words for maximum key size supported by HW natively. */
  kHmacMaxKeyWords = kHmacMaxKeyBits / sizeof(uint32_t) / 8,

  /* Number of bits for maximum digest size supported by HW natively. */
  kHmacMaxDigestBits = 512,
  /* Number of words for maximum digest size supported by HW natively. */
  kHmacMaxDigestWords = kHmacMaxDigestBits / sizeof(uint32_t) / 8,
  
  /* Number of bits for maximum internal SHA-2 blocks size supported by HW natively. */
  kHmacMaxBlockBits = 1024,
  /* Number of bytes for maximum internal SHA-2 blocks size supported by HW natively. */
  kHmacMaxBlockBytes = kHmacMaxBlockBits / 8,
  /* Number of words for maximum internal SHA-2 blocks size supported by HW natively. */
  kHmacMaxBlockWords = kHmacMaxBlockBytes / sizeof(uint32_t),
};

/**
 * A typed representation of the HMAC or SHA2 digests.
 */
typedef struct hmac_digest {
  uint32_t digest[kHmacMaxDigestWords];
  // Length of `digest` in bytes.
  size_t len;
} hmac_digest_t;

/**
 * A typed representation of an HMAC key.
 * HW supports 128, 256, 384, 512, 1024 bit keys.
 */
typedef struct hmac_key {
  uint32_t key[kHmacMaxKeyWords];
  // Length of `key` in bytes.
  size_t len;
} hmac_key_t;

/**
 * A context struct maintained for streaming operations.
 */
typedef struct hmac_ctx {
  // Back up cfg register, except SHA bit.
  uint32_t cfg_reg;
  // Need to keep some extra info around to reconfigure HW every time.
  uint32_t key[kHmacMaxKeyWords];
  // Length of `key` in words.
  size_t key_len;
  // The internal block size of HMAC/SHA2 in bytes.
  size_t msg_block_len;
  size_t digest_len;
  // The following fields are saved and restored during streaming.
  uint32_t H[kHmacMaxDigestWords];
  uint32_t lower;
  uint32_t upper;
  // The following are flags exclusively used by the driver to make whether
  // or not the driver needs to pass the incoming requests to HMAC IP.
  uint32_t hw_started;
  uint8_t partial_block[kHmacMaxBlockBytes];
  // The number of valid bytes in `partial_block`.
  size_t partial_block_len;
} hmac_ctx_t;

typedef enum hmac_mode {
  // SHA2-256
  kHmacModeSha256,
  // SHA2-384
  kHmacModeSha384,
  // SHA2-512
  kHmacModeSha512,
  // HMAC-256
  kHmacModeHmac256,
  // HMAC-384
  kHmacModeHmac384,
  // HMAC-512
  kHmacModeHmac512,
} hmac_mode_t;


/**
 * Initializes the context `ctx` according to given `hmac_mode` and `key`.
 *
 * This function does not invoke HMAC HWIP operation, but instead prepares `ctx`
 * with necessary data for streaming operations:
 * i) Copy given key and length into `ctx`.
 * ii) Prepare CFG register value (except `sha_en` bit) to be reloaded into
 * HMAC's CSR for every update operation.
 * iii) Initialize `hw_started` flag which indicates whether the very first
 * HMAC HWIP operation is executed or not. This helps decide whether START or
 * CONTINUE operation needs to be issues to HWIP.
 * iv) Compute and store message block length and digest len to be used for the
 * future calls.

 * For SHA-2 operation, `key` must be set to NULL.
 * For HMAC operations, the key length must be either of 128, 256, 384, 512 or
 * 1024 bits, which are only values supported natively by HWIP.
 *
 * @param ctx Context object for SHA2/HMAC-SHA2 operations.
 * @param hmac_mode Specifies the mode among SHA2-256/384/512, HMAC-256/384/512.
 * @param key HMAC key. The key to be used with HMAC calls.
  */
OT_WARN_UNUSED_RESULT
status_t hmac_init(hmac_ctx_t *ctx, const hmac_mode_t hmac_mode, const hmac_key_t *key);

/**
 * Sends `len` bytes from `data` to the HMAC or SHA2-256 function.
 *
 * This function does not check for the size of the available HMAC
 * FIFO. Since the this function is meant to run in blocking mode,
 * polling for FIFO status is equivalent to stalling on FIFO write.

 * Check if we have enough bits to invoke HMAC op.

i) if not,
    update the partial_block buffer
    update the length info
ii) if to be invoked
    hmac_halt()
    reload_cfg()
    reload_state()
    reload_lengths()
    hit hash_continue <-> keep feeding messages
    write leftoever to context
    store_lenghts()
    store_state()
    disable sha_en (to clear digest)
    wipe_secret()
 *
 * @param data Buffer to copy data from.
 * @param len size of the `data` buffer in bytes.
 */
void hmac_update(hmac_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * hmac_halt()
 * reload_config()
 * if not-empty, pad/feed last block
 * hit hash_process
 * read digest
 * wipe secret (need random input)
 *
 */
OT_WARN_UNUSED_RESULT
status_t hmac_final(hmac_ctx_t *ctx, hmac_digest_t *digest);

#ifdef __cplusplus
}
#endif

#endif  // OPENTITAN_SW_DEVICE_LIB_CRYPTO_DRIVERS_HMAC_H_
