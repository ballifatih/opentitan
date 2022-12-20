// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "external/xkcp/high/Keccak/SP800-185/SP800-185.h"

/**
 * Print given long byte array with hex characters.
 *
 * @param ptr Byte array pointer.
 * @param len Number of bytes to be printed.
 */
void print_long_array(uint8_t *ptr, size_t len) {
  for (size_t i = 0; i < len; ++i)
    printf("%02x", ptr[i]);
  printf("\n");
}

/**
 * Simple example for XKCP for KMAC test vector generation.
 */
int main(void) {
  unsigned char output[256 / 8];
  int err_status;

  const BitSequence key[] = {
      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
      0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
      0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
  };
  const BitSequence input[] = {0x00, 0x01, 0x02, 0x03};
  const BitSequence expected_output[] = {
      0xe5, 0x78, 0x0b, 0x0d, 0x3e, 0xa6, 0xf7, 0xd3, 0xa4, 0x29, 0xc5,
      0x70, 0x6a, 0xa4, 0x3a, 0x00, 0xfa, 0xdb, 0xd7, 0xd4, 0x96, 0x28,
      0x83, 0x9e, 0x31, 0x87, 0x24, 0x3f, 0x45, 0x6e, 0xe1, 0x4e};

  err_status = KMAC128(key, /*keyBitLen=*/8 * sizeof(key), input,
                       /*inputBitLen=*/8 * sizeof(input), output,
                       /*outputBitLen=*/8 * sizeof(output),
                       /*customization=*/NULL, /*customBitLen=*/0);
  if (err_status) {
    return err_status;
  }

  print_long_array(output, sizeof(output));

  return memcmp(expected_output, output, sizeof(output));
}
