// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/crypto/include/mac.h"

#include "sw/device/lib/base/hardened_memory.h"
#include "sw/device/lib/crypto/drivers/hmac.h"
#include "sw/device/lib/crypto/drivers/kmac.h"
#include "sw/device/lib/crypto/impl/integrity.h"
#include "sw/device/lib/crypto/impl/keyblob.h"
#include "sw/device/lib/crypto/impl/sha2/sha256.h"
#include "sw/device/lib/crypto/impl/sha2/sha512.h"
#include "sw/device/lib/crypto/impl/status.h"
#include "sw/device/lib/crypto/include/hash.h"

// Module ID for status codes.
#define MODULE_ID MAKE_MODULE_ID('m', 'a', 'c')

/**
 * Ensure that the hash context is large enough for HMAC driver struct.
 */
static_assert(
    sizeof(otcrypto_hmac_context_t) >= sizeof(hmac_ctx_t),
    "`otcrypto_hash_context_t` must be big enough to hold `hmac_ctx_t`.");

/**
 * Ensure that HMAC driver struct is suitable for `hardened_memcpy()`.
 */
static_assert(sizeof(hmac_ctx_t) % sizeof(uint32_t) == 0,
              "Size of `hmac_ctx_t` must be a multiple of the word size for "
              "`hardened_memcpy()`");

/**
 * Save the internal HMAC driver context to a generic Hmac context.
 *
 * @param[out] ctx Generic hash context to copy to.
 * @param hmac_ctx The internal context object from HMAC driver.
 */
static void hmac_ctx_save(otcrypto_hmac_context_t *restrict ctx,
                          const hmac_ctx_t *restrict hmac_ctx) {
  hardened_memcpy(ctx->data, (uint32_t *)hmac_ctx,
                  sizeof(hmac_ctx_t) / sizeof(uint32_t));
}

/**
 * Restore an internal HMAC driver context from a generic Hmac context.
 *
 * @param ctx Generic hash context to restore from.
 * @param[out] hmac_ctx Destination HMAC driver context object.
 */
static void hmac_ctx_restore(const otcrypto_hmac_context_t *restrict ctx,
                             hmac_ctx_t *restrict hmac_ctx) {
  hardened_memcpy((uint32_t *)hmac_ctx, ctx->data,
                  sizeof(hmac_ctx_t) / sizeof(uint32_t));
}

static status_t get_hmac_mode(otcrypto_key_mode_t key_mode,
                              hmac_mode_t *hmac_mode) {
  switch (key_mode) {
    case kOtcryptoKeyModeHmacSha256:
      *hmac_mode = kHmacModeHmac256;
      break;
    case kOtcryptoKeyModeHmacSha384:
      *hmac_mode = kHmacModeHmac384;
      break;
    case kOtcryptoKeyModeHmacSha512:
      *hmac_mode = kHmacModeHmac512;
      break;
    default:
      return OTCRYPTO_BAD_ARGS;
  }
  return OTCRYPTO_OK;
}

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_hmac(const otcrypto_blinded_key_t *key,
                                otcrypto_const_byte_buf_t input_message,
                                otcrypto_word32_buf_t tag) {
  // Validate key struct.
  if (key == NULL || key->keyblob == NULL || tag.data == NULL) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (key->config.hw_backed != kHardenedBoolFalse) {
    // TODO(#15590): Add support for sideloaded keys via a custom OTBN program.
    return OTCRYPTO_NOT_IMPLEMENTED;
  }
  if (key->config.security_level != kOtcryptoKeySecurityLevelLow) {
    // TODO: Harden SHA2 implementations.
    return OTCRYPTO_NOT_IMPLEMENTED;
  }

  // Check for null input message with nonzero length.
  if (input_message.data == NULL && input_message.len != 0) {
    return OTCRYPTO_BAD_ARGS;
  }

  // TODO: Once we have hardened SHA2, do not unmask the key here.
  size_t unmasked_key_len = keyblob_share_num_words(key->config);
  uint32_t unmasked_key[unmasked_key_len];
  HARDENED_TRY(keyblob_key_unmask(key, unmasked_key_len, unmasked_key));
  otcrypto_const_word32_buf_t hmac_key = {
      .data = unmasked_key,
      .len = unmasked_key_len,
  };

  hmac_mode_t hmac_mode;
  HARDENED_TRY(get_hmac_mode(key->config.key_mode, &hmac_mode));

  otcrypto_word32_buf_t hmac_digest = {
      .data = tag.data,
      .len = tag.len,
  };

  return hmac_oneshot(hmac_mode, &hmac_key, input_message.data,
                      input_message.len, &hmac_digest);
}

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_kmac(const otcrypto_blinded_key_t *key,
                                otcrypto_const_byte_buf_t input_message,
                                otcrypto_kmac_mode_t kmac_mode,
                                otcrypto_const_byte_buf_t customization_string,
                                size_t required_output_len,
                                otcrypto_word32_buf_t tag) {
  // TODO (#16410) Revisit/complete error checks

  // Check for null pointers.
  if (key == NULL || key->keyblob == NULL || tag.data == NULL) {
    return OTCRYPTO_BAD_ARGS;
  }

  // Check for null input message with nonzero length.
  if (input_message.data == NULL && input_message.len != 0) {
    return OTCRYPTO_BAD_ARGS;
  }

  // Check for null customization string with nonzero length.
  if (customization_string.data == NULL && customization_string.len != 0) {
    return OTCRYPTO_BAD_ARGS;
  }

  // Ensure that tag buffer length and `required_output_len` match each other.
  if (required_output_len != tag.len * sizeof(uint32_t) ||
      required_output_len == 0) {
    return OTCRYPTO_BAD_ARGS;
  }

  size_t key_len = keyblob_share_num_words(key->config) * sizeof(uint32_t);

  // Check `key_len` is valid/supported by KMAC HWIP.
  HARDENED_TRY(kmac_key_length_check(key_len));

  // Check the integrity of the blinded key.
  if (integrity_blinded_key_check(key) != kHardenedBoolTrue) {
    return OTCRYPTO_BAD_ARGS;
  }

  kmac_blinded_key_t kmac_key = {
      .share0 = NULL,
      .share1 = NULL,
      .hw_backed = key->config.hw_backed,
      .len = key_len,
  };

  if (key->config.hw_backed == kHardenedBoolTrue) {
    if (key_len != kKmacSideloadKeyLength / 8) {
      return OTCRYPTO_BAD_ARGS;
    }
    // Configure keymgr with diversification input and then generate the
    // sideload key.
    keymgr_diversification_t diversification;
    // Diversification call also checks that `key->keyblob_length` is 8 words
    // long.
    HARDENED_TRY(keyblob_to_keymgr_diversification(key, &diversification));
    HARDENED_TRY(keymgr_generate_key_kmac(diversification));
  } else if (key->config.hw_backed == kHardenedBoolFalse) {
    // Check `key_len` matches `keyblob_length`.
    if (key->keyblob_length != 2 * key->config.key_length) {
      return OTCRYPTO_BAD_ARGS;
    }
    HARDENED_TRY(keyblob_to_shares(key, &kmac_key.share0, &kmac_key.share1));
  } else {
    return OTCRYPTO_BAD_ARGS;
  }

  switch (kmac_mode) {
    case kOtcryptoKmacModeKmac128:
      // Check `key_mode` matches `mac_mode`
      if (key->config.key_mode != kOtcryptoKeyModeKmac128) {
        return OTCRYPTO_BAD_ARGS;
      }
      HARDENED_TRY(kmac_kmac_128(&kmac_key, input_message.data,
                                 input_message.len, customization_string.data,
                                 customization_string.len, tag.data, tag.len));
      break;
    case kOtcryptoKmacModeKmac256:
      // Check `key_mode` matches `mac_mode`
      if (key->config.key_mode != kOtcryptoKeyModeKmac256) {
        return OTCRYPTO_BAD_ARGS;
      }

      HARDENED_TRY(kmac_kmac_256(&kmac_key, input_message.data,
                                 input_message.len, customization_string.data,
                                 customization_string.len, tag.data, tag.len));
      break;
    default:
      return OTCRYPTO_BAD_ARGS;
  }

  if (key->config.hw_backed == kHardenedBoolTrue) {
    HARDENED_TRY(keymgr_sideload_clear_kmac());
  } else if (key->config.hw_backed != kHardenedBoolFalse) {
    return OTCRYPTO_BAD_ARGS;
  }

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_hmac_init(otcrypto_hmac_context_t *ctx,
                                     const otcrypto_blinded_key_t *key) {
  if (ctx == NULL || key == NULL || key->keyblob == NULL) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (key->config.hw_backed != kHardenedBoolFalse) {
    // TODO(#15590): Add support for sideloaded keys via a custom OTBN program.
    return OTCRYPTO_NOT_IMPLEMENTED;
  }
  if (key->config.security_level != kOtcryptoKeySecurityLevelLow) {
    // TODO: Harden SHA2 implementations.
    return OTCRYPTO_NOT_IMPLEMENTED;
  }

  // TODO: Once we have hardened SHA2, do not unmask the key here.
  size_t unmasked_key_len = keyblob_share_num_words(key->config);
  uint32_t unmasked_key[unmasked_key_len];
  HARDENED_TRY(keyblob_key_unmask(key, unmasked_key_len, unmasked_key));
  otcrypto_const_word32_buf_t hmac_key = {
      .data = unmasked_key,
      .len = unmasked_key_len,
  };

  // Ensure the key is for HMAC and the hash function matches, and remember the
  // digest and message block sizes.
  hmac_mode_t hmac_mode;
  HARDENED_TRY(get_hmac_mode(key->config.key_mode, &hmac_mode));

  hmac_ctx_t hmac_ctx;
  HARDENED_TRY(hmac_init(&hmac_ctx, hmac_mode, &hmac_key));
  hmac_ctx_save(ctx, &hmac_ctx);
  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_hmac_update(
    otcrypto_hmac_context_t *const ctx,
    otcrypto_const_byte_buf_t input_message) {
  if (ctx == NULL) {
    return OTCRYPTO_BAD_ARGS;
  }

  // Check for null input message with nonzero length.
  if (input_message.data == NULL && input_message.len != 0) {
    return OTCRYPTO_BAD_ARGS;
  }

  hmac_ctx_t hmac_ctx;
  hmac_ctx_restore(ctx, &hmac_ctx);
  HARDENED_TRY(hmac_update(&hmac_ctx, input_message.data, input_message.len));
  hmac_ctx_save(ctx, &hmac_ctx);
  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_hmac_final(otcrypto_hmac_context_t *const ctx,
                                      otcrypto_word32_buf_t tag) {
  if (ctx == NULL || tag.data == NULL) {
    return OTCRYPTO_BAD_ARGS;
  }

  hmac_ctx_t hmac_ctx;
  otcrypto_word32_buf_t hmac_digest = {
      .data = tag.data,
      .len = tag.len,
  };
  hmac_ctx_restore(ctx, &hmac_ctx);
  HARDENED_TRY(hmac_final(&hmac_ctx, &hmac_digest));
  // TODO(#23191): Clear `ctx`.
  hmac_ctx_save(ctx, &hmac_ctx);
  return OTCRYPTO_OK;
}
