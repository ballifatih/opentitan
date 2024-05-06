// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef OPENTITAN_SW_DEVICE_LIB_CRYPTO_DRIVERS_HMAC_H_
#define OPENTITAN_SW_DEVICE_LIB_CRYPTO_DRIVERS_HMAC_H_

#include <stddef.h>
#include <stdint.h>

#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/base/hardened.h"

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
};

/**
 * Digest length supported by hardware. This is another way of referring to 
 * SHA2-256, SHA2-384 and SHA2-512 (as well as HMAC functions with the same
 * digest size).
 */
typedef enum hmac_digest_len {
  kHmacDigestLen256 = HMAC_CFG_DIGEST_SIZE_VALUE_SHA2_256,
  kHmacDigestLen384 = HMAC_CFG_DIGEST_SIZE_VALUE_SHA2_384,
  kHmacDigestLen512 = HMAC_CFG_DIGEST_SIZE_VALUE_SHA2_512,
} hmac_digest_len_t;

/**
 * Key lengths natively supported by HW.
 */
typedef enum hmac_key_len {
  kHmacKeyLen128 = HMAC_CFG_KEY_LENGTH_VALUE_KEY_128,
  kHmacKeyLen256 = HMAC_CFG_KEY_LENGTH_VALUE_KEY_256,
  kHmacKeyLen384 = HMAC_CFG_KEY_LENGTH_VALUE_KEY_384,
  kHmacKeyLen512 = HMAC_CFG_KEY_LENGTH_VALUE_KEY_512,
  kHmacKeyLen1024 = HMAC_CFG_KEY_LENGTH_VALUE_KEY_1024,
} hmac_key_len_t;


/**
 * A typed representation of the HMAC or SHA256 digest.
 */
typedef struct hmac_digest {
  uint32_t digest[8];
  size_t len; // in bytes
} hmac_digest_t;

/**
 * A typed representation of an HMAC key.
 */
typedef struct hmac_key {
  uint32_t key[8];
  size_t len; // in bytes
} hmac_key_t;


typedef struct hmac_ctx {
  // Need to keep some extra info around to reconfigure HW every time.
  uint32_t key[32];
  hmac_digest_len_t digest_len;
  hmac_key_len_t key_len;
  hardened_bool_t enable_hmac;
  // The following are directly stored/loaded from HW.
  uint32_t H[16];
  uint32_t lower;
  uint32_t upper;
  // The following are SW-managed partial state
  uint32_t hw_started;
  uint8_t partial_block[128];
  // The following has bytes as unit.
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
 * Initializes the context `ctx` according to given `hmac_mode`.
 *
 * This function does not actually invoke any HW operation, but instead
 * it populates the `ctx` struct properly. The caller is responsible for
 * allocating memory for the pointers from `ctx`'s members.
 *
 * @param ctx Context object for SHA2/HMAC-SHA2 operations.
 * @param hmac_mode Specifies the mode among SHA2-256/384/512, HMAC-256/384/512.
 * @param key HMAC key. The key to be used with HMAC calls. For SHA-2 operations,
 * this input is irrelevant, and NULL pointer can be passed.
  */
void hmac_init(hmac_ctx_t *ctx, const hmac_mode_t hmac_mode, const hmac_key_t *key);

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
void hmac_final(hmac_ctx_t *ctx, hmac_digest_t *digest);

#ifdef __cplusplus
}
#endif

#endif  // OPENTITAN_SW_DEVICE_LIB_CRYPTO_DRIVERS_HMAC_H_
