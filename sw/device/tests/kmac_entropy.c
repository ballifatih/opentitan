// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/testing/entropy_testutils.h" // not sure if needed

#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include "sw/device/lib/dif/dif_kmac.h"
#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/base/macros.h"
#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"

OTTF_DEFINE_TEST_CONFIG(.enable_concurrency = false,
                        .can_clobber_uart = false, );

#define DIGEST_LEN_KMAC_MAX 100

/**
 * KMAC test description.
 */
typedef struct kmac_test {
  dif_kmac_mode_kmac_t mode;
  dif_kmac_key_t key;

  const char *message;
  size_t message_len;

  const char *customization_string;
  size_t customization_string_len;

  const uint32_t digest[DIGEST_LEN_KMAC_MAX];
  size_t digest_len;
  bool digest_len_is_fixed;
} kmac_test_t;

/**
 * A single KMAC example:
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
 */
const kmac_test_t kmac_test_vector = {
  .mode = kDifKmacModeKmacLen256,
  .key =
      (dif_kmac_key_t){
          .share0 = {0x43424140, 0x47464544, 0x4B4A4948, 0x4F4E4D4C,
                     0x53525150, 0x57565554, 0x5B5A5958, 0x5F5E5D5C},
          .share1 = {0},
          .length = kDifKmacKeyLen256,
      },
  .message =
      "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
      "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
      "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
      "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
      "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
      "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
      "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
      "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
      "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
      "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
      "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
      "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
      "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7",
  .message_len = 200,
  .customization_string = "My Tagged Application",
  .customization_string_len = 21,
  .digest = {0x1C73BED5, 0x73D74E95, 0x59BB4628, 0xE3A8E3DB, 0x7AE7830F,
             0x5944FF4B, 0xB4C2F1F2, 0xCEB8EBEC, 0xC601BA67, 0x57B88A2E,
             0x9B492D8D, 0x6727BBD1, 0x90117868, 0x6A300A02, 0x1D28DE97,
             0x5D3030CC},
  .digest_len = 16,
  .digest_len_is_fixed = false,
};

bool test_main(void) {
  LOG_INFO("Running KMAC ENTROPY test...");
  //entropy_testutils_auto_mode_init();

  // Initialize KMAC HWIP.
  dif_kmac_t kmac;
  dif_kmac_operation_state_t kmac_operation_state;
  CHECK_DIF_OK(
      dif_kmac_init(mmio_region_from_addr(TOP_EARLGREY_KMAC_BASE_ADDR), &kmac));

  // Configure KMAC to use EDN entropy
  // Set max values for the EDN timeout
  dif_kmac_config_t config = (dif_kmac_config_t){
      .entropy_mode = kDifKmacEntropyModeEdn,
      .entropy_fast_process = false,
      .entropy_seed = {0x1, 0x1, 0x1, 0x1, 0x1},
      .entropy_hash_threshold = 0x3FF,
      .entropy_wait_timer = 0xFFFF,
      //.entropy_wait_timer = 0x0000,
      .entropy_prescaler = 0x03FF,
      .message_big_endian = false,
      .output_big_endian = false,
      .sideload = false,
      .msg_mask = false,
  };
  CHECK_DIF_OK(dif_kmac_configure(&kmac, config));

  // Handle string encoding
  dif_kmac_customization_string_t str_buffer;
    CHECK_DIF_OK(dif_kmac_customization_string_init(
        kmac_test_vector.customization_string, 
        kmac_test_vector.customization_string_len, &str_buffer));

  // When customization_string is empty, use NULL to activate empty str path
  dif_kmac_customization_string_t *s_buff=
        kmac_test_vector.customization_string_len == 0 ? NULL : &str_buffer;

  size_t digest_l = kmac_test_vector.digest_len_is_fixed ? kmac_test_vector.digest_len : 0;
  CHECK_DIF_OK(dif_kmac_mode_kmac_start(&kmac, 
                                          &kmac_operation_state,
                                          kmac_test_vector.mode, 
                                          digest_l, 
                                          &kmac_test_vector.key, 
                                          s_buff));

  // Absorbing stage
  CHECK_DIF_OK(dif_kmac_absorb(&kmac, 
                              &kmac_operation_state, kmac_test_vector.message,
                                 kmac_test_vector.message_len, NULL));

  uint32_t out[DIGEST_LEN_KMAC_MAX];
  CHECK(DIGEST_LEN_KMAC_MAX >= kmac_test_vector.digest_len);

  //CHECK_DIF_OK(dif_kmac_squeeze(&kmac, &kmac_operation_state, out,
  //                                kmac_test_vector.digest_len, NULL));
  dif_result_t res = dif_kmac_squeeze(&kmac, &kmac_operation_state, out, kmac_test_vector.digest_len, NULL);

  dif_kmac_error_t err;

  // Either squeeze is successful or it timedout.
  CHECK(res == kDifOk || res == kInternal);
  if (res == kDifOk) {
    LOG_INFO("No EDN timeout");
  } else if (res == kInternal) {
    CHECK_DIF_OK(dif_kmac_get_error(&kmac, &err));
    // Print the raw value of ERR_CODE register
    LOG_INFO("err = %08X", err);
    CHECK(kDifErrorEntropyWaitTimerExpired == err);
    LOG_INFO("Entropy Timeout");
  } else {
    CHECK(false, "Squeeze failed for a reason other than EDN timeout.");
  }

  return true;
}
