// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/crypto/drivers/entropy.h"
#include "sw/device/lib/crypto/drivers/hmac.h"
#include "sw/device/lib/crypto/impl/integrity.h"
#include "sw/device/lib/crypto/include/datatypes.h"
#include "sw/device/lib/crypto/include/hash.h"
#include "sw/device/lib/crypto/include/mac.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

// The autogen rule that creates this header creates it in a directory named
// after the rule, then manipulates the include path in the
// cc_compilation_context to include that directory, so the compiler will find
// the version of this file matching the Bazel rule under test.
#include "hmac_testvectors.h"

// Module ID for status codes.
#define MODULE_ID MAKE_MODULE_ID('h', 'm', 'a')

static_assert(sizeof(otcrypto_hash_context_t) ==
              sizeof(otcrypto_hmac_context_t),
              "Hash and Hmac contexts are expected to be of the same length");

// Global pointer to the current test vector.
static otcrypto_hmac_context_t hmac_contexts[ARRAYSIZE(kHmacTestVectors)];
static otcrypto_hash_context_t hash_contexts[ARRAYSIZE(kHmacTestVectors)];


/**
 * Determines `hash_mode` for given SHA-2 test vectors.
 *
 * Note that for HMAC operations, mode information is part of the key struct,
 * hence this function is only used for hash vectors.
 *
 * @param test_vec The pointer to the test vector.
 * @param[out] hash_mode The determined hash_mode of the given test vector.
 */
static status_t get_hash_mode(hmac_test_vector_t *test_vec,
                              otcrypto_hash_mode_t *hash_mode) {
  switch (test_vec->test_operation) {
    case kHmacTestOperationSha256:
      *hash_mode = kOtcryptoHashModeSha256;
      return OTCRYPTO_OK;
    case kHmacTestOperationSha384:
      *hash_mode = kOtcryptoHashModeSha384;
      return OTCRYPTO_OK;
    case kHmacTestOperationSha512:
      *hash_mode = kOtcryptoHashModeSha512;
      return OTCRYPTO_OK;
    default:
      return OTCRYPTO_BAD_ARGS;
  }
}

/**
 * Instantiate the ctx object for the vector at index `i`.
 */
static status_t ctx_init(size_t i) {
  // Populate `checksum` and `config.security_level` fields.
  hmac_test_vector_t *current_test_vector = &kHmacTestVectors[i];
  current_test_vector->key.checksum =
      integrity_blinded_checksum(&current_test_vector->key);
  
  otcrypto_hash_mode_t hash_mode;

  switch (current_test_vector->test_operation) {
    case kHmacTestOperationSha256:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationSha384:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationSha512:
      LOG_INFO("Invoking hash_init for %s.",
               current_test_vector->vector_identifier);
      TRY(get_hash_mode(current_test_vector, &hash_mode));
      TRY(otcrypto_hash_init(&hash_contexts[i], hash_mode));
      break;
    case kHmacTestOperationHmacSha256:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationHmacSha384:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationHmacSha512:
      LOG_INFO("Invoking hmac_init for %s.",
               current_test_vector->vector_identifier);
      TRY(otcrypto_hmac_init(&hmac_contexts[i], &current_test_vector->key));
      break;
    default:
      return OTCRYPTO_BAD_ARGS;
  }
  return OTCRYPTO_OK;
}

/**
 * Run the test pointed to by `current_test_vector`.
 */
static status_t feed_msg_1(size_t i) {
  hmac_test_vector_t *current_test_vector = &kHmacTestVectors[i];
  // Allocate the buffer for the maximum digest size.
  size_t break_index = current_test_vector->message.len / 2;
  otcrypto_const_byte_buf_t msg_part1 = {
      .data = current_test_vector->message.data,
      .len = break_index,
  };
  switch (current_test_vector->test_operation) {
    case kHmacTestOperationSha256:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationSha384:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationSha512:
      LOG_INFO("Invoking hash_update (msg1) for %s.",
               current_test_vector->vector_identifier);
      TRY(otcrypto_hash_update(&hash_contexts[i], msg_part1));
      break;
    case kHmacTestOperationHmacSha256:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationHmacSha384:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationHmacSha512:
      LOG_INFO("Invoking hmac_update (msg1) for %s.",
               current_test_vector->vector_identifier);
      TRY(otcrypto_hmac_update(&hmac_contexts[i], msg_part1));
      break;
    default:
      return OTCRYPTO_BAD_ARGS;
  }
  return OTCRYPTO_OK;
}

/**
 * Run the test pointed to by `current_test_vector`.
 */
static status_t feed_msg_2(size_t i) {
  hmac_test_vector_t *current_test_vector = &kHmacTestVectors[i];
  // Allocate the buffer for the maximum digest size.
  size_t break_index = current_test_vector->message.len / 2;
  otcrypto_const_byte_buf_t msg_part2 = {
      .data = &current_test_vector->message.data[break_index],
      .len = current_test_vector->message.len - break_index,
  };
  switch (current_test_vector->test_operation) {
    case kHmacTestOperationSha256:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationSha384:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationSha512:
      LOG_INFO("Invoking hash_update (msg2) for %s.",
               current_test_vector->vector_identifier);
      TRY(otcrypto_hash_update(&hash_contexts[i], msg_part2));
      break;
    case kHmacTestOperationHmacSha256:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationHmacSha384:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationHmacSha512:
      LOG_INFO("Invoking hmac_update (msg2) for %s.",
               current_test_vector->vector_identifier);
      TRY(otcrypto_hmac_update(&hmac_contexts[i], msg_part2));
      break;
    default:
      return OTCRYPTO_BAD_ARGS;
  }
  return OTCRYPTO_OK;
}

/**
 * Run the test pointed to by `current_test_vector`.
 */
static status_t hmac_finalize(size_t i) {
  hmac_test_vector_t *current_test_vector = &kHmacTestVectors[i];
  // The test vectors already have the correct digest sizes hardcoded.
  size_t digest_len = current_test_vector->digest.len;
  // Allocate the buffer for the maximum digest size.
  uint32_t act_tag[kHmacMaxDigestBits];
  otcrypto_word32_buf_t tag_buf = {
      .data = act_tag,
      .len = digest_len,
  };
  otcrypto_hash_digest_t hash_digest = {
      // .mode is to be determined below in switch-case block.
      .data = act_tag,
      .len = digest_len,
  };
  switch (current_test_vector->test_operation) {
    case kHmacTestOperationSha256:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationSha384:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationSha512:
      LOG_INFO("Invoking hash_final for %s.",
               current_test_vector->vector_identifier);
      TRY(otcrypto_hash_final(&hash_contexts[i], hash_digest));
      break;
    case kHmacTestOperationHmacSha256:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationHmacSha384:
      OT_FALLTHROUGH_INTENDED;
    case kHmacTestOperationHmacSha512:
      LOG_INFO("Invoking hmac_final for %s.",
               current_test_vector->vector_identifier);
      TRY(otcrypto_hmac_final(&hmac_contexts[i], tag_buf));
      break;
    default:
      return OTCRYPTO_BAD_ARGS;
  }
  LOG_INFO("Comparing result for %s.",
           current_test_vector->vector_identifier);
  TRY_CHECK_ARRAYS_EQ(act_tag, current_test_vector->digest.data, digest_len);
  return OTCRYPTO_OK;
}

static status_t run_test(void) {
  for (size_t i = 0; i < ARRAYSIZE(kHmacTestVectors); i++) {
    TRY(ctx_init(i));  
  }
  for (size_t i = 0; i < ARRAYSIZE(kHmacTestVectors); i++) {
    TRY(feed_msg_1(i));
  }
  for (size_t i = 0; i < ARRAYSIZE(kHmacTestVectors); i++) {
    TRY(feed_msg_2(i));
  }
  for (size_t i = 0; i < ARRAYSIZE(kHmacTestVectors); i++) {
    TRY(hmac_finalize(i));
  }
  return OTCRYPTO_OK;
}

OTTF_DEFINE_TEST_CONFIG();
bool test_main(void) {
  LOG_INFO("Testing cryptolib HMAC driver.");
  CHECK_STATUS_OK(entropy_complex_init());
  status_t test_result = OK_STATUS();
  EXECUTE_TEST(test_result, run_test);
  return status_ok(test_result);
}
