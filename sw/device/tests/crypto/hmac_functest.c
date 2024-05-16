// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/crypto/drivers/entropy.h"
#include "sw/device/lib/crypto/drivers/hmac.h"
#include "sw/device/lib/crypto/impl/integrity.h"
#include "sw/device/lib/crypto/include/datatypes.h"
#include "sw/device/lib/crypto/include/hash.h"
#include "sw/device/lib/crypto/include/kdf.h"
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

// Global pointer to the current test vector.
static hmac_test_vector_t *current_test_vector = NULL;

/**
 * Run the test pointed to by `current_test_vector`.
 */
static status_t run_test_vector(void) {

  // Populate `checksum` and `config.security_level` fields.
  current_test_vector->key.checksum = 
      integrity_blinded_checksum(&current_test_vector->key);

  otcrypto_hmac_context_t hmac_ctx;
  otcrypto_hash_context_t hash_ctx;

  // TODO handle larger digest sizes.
  uint32_t act_tag[8];
  otcrypto_word32_buf_t tag_buf = {
      .data = act_tag,
      .len = ARRAYSIZE(act_tag),
  };
  otcrypto_hash_digest_t hash_digest = {
    .mode = kOtcryptoHashModeSha256,
    .data = act_tag,
    .len = 8,
  };
  size_t break_index = current_test_vector->message.len / 2;
  otcrypto_const_byte_buf_t msg_part1 = {
    .data = current_test_vector->message.data,
    .len = break_index,
  };
  otcrypto_const_byte_buf_t msg_part2 = {
    .data = &current_test_vector->message.data[break_index],
    .len = current_test_vector->message.len - break_index,
  }; 
  if(current_test_vector->test_operation == kHmacTestOperationSha256) {
    //TRY(otcrypto_hash(current_test_vector->message, hash_digest));
    TRY(otcrypto_hash_init(&hash_ctx, kOtcryptoHashModeSha256));
    TRY(otcrypto_hash_update(&hash_ctx, msg_part1));
    TRY(otcrypto_hash_update(&hash_ctx, msg_part2));
    TRY(otcrypto_hash_final(&hash_ctx, hash_digest));
  } else if (current_test_vector->test_operation == kHmacTestOperationHmacSha256) {
    //TRY(otcrypto_hmac(&current_test_vector->key, current_test_vector->message, tag_buf));
    
    TRY(otcrypto_hmac_init(&hmac_ctx, &current_test_vector->key));
    TRY(otcrypto_hmac_update(&hmac_ctx, msg_part1));
    TRY(otcrypto_hmac_update(&hmac_ctx, msg_part2));
    TRY(otcrypto_hmac_final(&hmac_ctx, tag_buf));

  }
  TRY_CHECK_ARRAYS_EQ(act_tag, current_test_vector->digest.data, 8);    
  return OTCRYPTO_OK;
}

OTTF_DEFINE_TEST_CONFIG();
bool test_main(void) {
  LOG_INFO("Testing cryptolib HMAC driver.");
  CHECK_STATUS_OK(entropy_complex_init());
  status_t test_result = OK_STATUS();
  for (size_t i = 0; i < ARRAYSIZE(kHmacTestVectors); i++) {
    current_test_vector = &kHmacTestVectors[i];
    LOG_INFO("Running test %d of %d, test vector identifier: %s", i + 1,
             ARRAYSIZE(kHmacTestVectors),
             current_test_vector->vector_identifier);
    EXECUTE_TEST(test_result, run_test_vector);
  }
  return status_ok(test_result);
}
