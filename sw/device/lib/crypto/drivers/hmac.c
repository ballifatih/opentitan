// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/crypto/drivers/hmac.h"

#include "sw/device/lib/base/abs_mmio.h"
#include "sw/device/lib/base/bitfield.h"
#include "sw/device/lib/base/hardened.h"
#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/crypto/impl/status.h"

#include "hmac_regs.h"  // Generated.
#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"

// Module ID for status codes.
#define MODULE_ID MAKE_MODULE_ID('d', 'h', 'm')

OT_ASSERT_ENUM_VALUE(HMAC_KEY_1_REG_OFFSET, HMAC_KEY_0_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_2_REG_OFFSET, HMAC_KEY_1_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_3_REG_OFFSET, HMAC_KEY_2_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_4_REG_OFFSET, HMAC_KEY_3_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_5_REG_OFFSET, HMAC_KEY_4_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_6_REG_OFFSET, HMAC_KEY_5_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_7_REG_OFFSET, HMAC_KEY_6_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_8_REG_OFFSET, HMAC_KEY_7_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_9_REG_OFFSET, HMAC_KEY_8_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_10_REG_OFFSET, HMAC_KEY_9_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_11_REG_OFFSET, HMAC_KEY_10_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_12_REG_OFFSET, HMAC_KEY_11_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_13_REG_OFFSET, HMAC_KEY_12_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_14_REG_OFFSET, HMAC_KEY_13_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_15_REG_OFFSET, HMAC_KEY_14_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_16_REG_OFFSET, HMAC_KEY_15_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_17_REG_OFFSET, HMAC_KEY_16_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_18_REG_OFFSET, HMAC_KEY_17_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_19_REG_OFFSET, HMAC_KEY_18_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_20_REG_OFFSET, HMAC_KEY_19_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_21_REG_OFFSET, HMAC_KEY_20_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_22_REG_OFFSET, HMAC_KEY_21_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_23_REG_OFFSET, HMAC_KEY_22_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_24_REG_OFFSET, HMAC_KEY_23_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_25_REG_OFFSET, HMAC_KEY_24_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_26_REG_OFFSET, HMAC_KEY_25_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_27_REG_OFFSET, HMAC_KEY_26_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_28_REG_OFFSET, HMAC_KEY_27_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_29_REG_OFFSET, HMAC_KEY_28_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_30_REG_OFFSET, HMAC_KEY_29_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_KEY_31_REG_OFFSET, HMAC_KEY_30_REG_OFFSET + 4);

OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_1_REG_OFFSET, HMAC_DIGEST_0_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_2_REG_OFFSET, HMAC_DIGEST_1_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_3_REG_OFFSET, HMAC_DIGEST_2_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_4_REG_OFFSET, HMAC_DIGEST_3_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_5_REG_OFFSET, HMAC_DIGEST_4_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_6_REG_OFFSET, HMAC_DIGEST_5_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_7_REG_OFFSET, HMAC_DIGEST_6_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_8_REG_OFFSET, HMAC_DIGEST_7_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_9_REG_OFFSET, HMAC_DIGEST_8_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_10_REG_OFFSET, HMAC_DIGEST_9_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_11_REG_OFFSET, HMAC_DIGEST_10_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_12_REG_OFFSET, HMAC_DIGEST_11_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_13_REG_OFFSET, HMAC_DIGEST_12_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_14_REG_OFFSET, HMAC_DIGEST_13_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(HMAC_DIGEST_15_REG_OFFSET, HMAC_DIGEST_14_REG_OFFSET + 4);

enum {
  kHmacBaseAddr = TOP_EARLGREY_HMAC_BASE_ADDR,
  // Block size for SHA-256 in bits, bytes and words, respectively.
  kHmacSha256BlockBits = 512,
  kHmacSha256BlockBytes = kHmacSha256BlockBits / 8,
  kHmacSha256BlockWords = kHmacSha256BlockBytes / 4,
  // Digest size for SHA-256 in bits, bytes and words, respectively,
  kHmacSha256DigestBits = 256,
  kHmacSha256DigestBytes = kHmacSha256DigestBits / 8,
  kHmacSha256DigestWords = kHmacSha256DigestBytes / 4,
};

/**
 * Wait until HMAC raises `hmac_done` interrupt. After interrupt is observed,
 * clear it.
 *
 * TODO(#22916): Avoid constant loop and use to-be-implemented Idle/status bit
 * instead.
 */
static void wait_hmac_done(void) {
  uint32_t intr_reg = 0;
  while(bitfield_bit32_read(intr_reg, HMAC_INTR_STATE_HMAC_DONE_BIT) == 0) {
    intr_reg = abs_mmio_read32(kHmacBaseAddr + HMAC_INTR_STATE_REG_OFFSET);
  }

  // Clear the interrupt by writing 1, because `INTR_STATE` is rw1c type.
  abs_mmio_write32(kHmacBaseAddr + HMAC_INTR_STATE_REG_OFFSET, intr_reg);
}

/**
 * Clear the state of HMAC HWIP so that further driver calls can use it.
 *
 * This function cannot force stop HWIP, and ongoing operations will not simply
 * stop by deasserting `sha_en` bit. Instead it should be used after HWIP
 * raises `hmac_done` interrupt (see `wait_hmac_done` function).
 *
 * It also clears the internal state of HWIP by overwriting sensitive values
 * with 1s. 
 */
static void hmac_hwip_clear(void) {
  // Do not clear the config yet, we just need to deassert sha_en, see #23014.
  // TODO handle digest size changes.
  uint32_t cfg_reg = abs_mmio_read32(kHmacBaseAddr + HMAC_CFG_REG_OFFSET);
  cfg_reg = bitfield_bit32_write(cfg_reg, HMAC_CFG_SHA_EN_BIT, false);
  abs_mmio_write32(kHmacBaseAddr + HMAC_CFG_REG_OFFSET, cfg_reg);

  // Wipe secrets (e.g. key).
  // TODO: this value is used directy by the HMAC hardware to overwrite the
  // key; replace it with a random number read from Ibex's RND.
  abs_mmio_write32(kHmacBaseAddr + HMAC_WIPE_SECRET_REG_OFFSET, UINT32_MAX);
}

/**
 * Update `CFG` register based on the passed `ctx`. This function updates all
 * fields of `CFG` except `sha_en`.
 *
 * The driver does not expose endianness options, therefore `digest_swap` and
 * `endian_swap` bits are hardcoded,
 *
 * @param ctx A pointer to the context which determines the CFG values to be
 * written.
 */
static void write_config_to_csr(const hmac_ctx_t *ctx) {
  uint32_t cfg_reg = HMAC_CFG_REG_RESVAL;

  // The endianness is fixed at driver level and not exposed to the caller.
  // Digest should be big-endian to match the SHA-256 specification.
  cfg_reg = bitfield_bit32_write(cfg_reg, HMAC_CFG_DIGEST_SWAP_BIT, true);
  // Message should be little-endian to match Ibex's endianness.
  cfg_reg = bitfield_bit32_write(cfg_reg, HMAC_CFG_ENDIAN_SWAP_BIT, false);

  // We need to keep `sha_en` low until context is restored, see #23014.
  cfg_reg = bitfield_bit32_write(cfg_reg, HMAC_CFG_SHA_EN_BIT, false);
  if (launder32(ctx->enable_hmac) == kHardenedBoolTrue) {
    HARDENED_CHECK_EQ(ctx->enable_hmac, kHardenedBoolTrue);
    cfg_reg = bitfield_bit32_write(cfg_reg, HMAC_CFG_HMAC_EN_BIT, true);
  } else {
    HARDENED_CHECK_EQ(ctx->enable_hmac, kHardenedBoolFalse);
    cfg_reg = bitfield_bit32_write(cfg_reg, HMAC_CFG_HMAC_EN_BIT, false);
  }

  // TODO remove hardcoded digest size
  cfg_reg = bitfield_field32_write(cfg_reg, HMAC_CFG_DIGEST_SIZE_FIELD,
                               ctx->digest_len);
                               
 // TODO remove hardcoded key size
  cfg_reg = bitfield_field32_write(cfg_reg, HMAC_CFG_KEY_LENGTH_FIELD,
                               ctx->key_len);

  abs_mmio_write32(kHmacBaseAddr + HMAC_CFG_REG_OFFSET, cfg_reg);
}

/**
 * Write the key into key registers.
 *
 * The key words and the key length are inferred from `ctx`. This function
 * should only be called during HMAC functions, but not SHA2.
 *
 * @param ctx A pointer to the context which determines the CFG values to be
 * written.
 * @param word_len The size of the key in 32-bit words.
 */
static void write_key(uint32_t *key, size_t word_len) {
  // TODO: A potential point to harden.
  for(size_t i = 0; i < word_len; i++) {
    abs_mmio_write32(kHmacBaseAddr + HMAC_KEY_0_REG_OFFSET + 4*i, key[i]);
  }
}

/**
 * Restore the internal state of HWIP from `ctx` struct, and resume the
 * operation.
 *
 * The first HWIP operation requires the call of `start` instead of `continue`.
 * Therefore, `ctx->hw_started` flag is used to distinguish the first call. This
 * function also updated `ctx->hw_started` after the first such call.
 *
 * If this function is being called from `ctx` object with previously stored
 * context (i.e. `ctx->hw_started = true`), then this state is restored.
 */
static void restore_context(hmac_ctx_t *ctx) {
  write_config_to_csr(ctx);

  uint32_t cmd_reg = HMAC_CMD_REG_RESVAL;
  // Decide if we need to invoke `start` or `continue` command.

  // TODO handle other key sizes
  if (ctx->enable_hmac == kHardenedBoolTrue) {
    write_key(ctx->key, 8);
  }


  if(ctx->hw_started) {
      cmd_reg = bitfield_bit32_write(cmd_reg, HMAC_CMD_HASH_CONTINUE_BIT, 1);

      // TODO: Remove hard coded digest len.
      // TODO: Could be hardened for HMAC.
      for(size_t i = 0; i < 8; i++) {
        abs_mmio_write32(kHmacBaseAddr + HMAC_DIGEST_0_REG_OFFSET + 4*i, ctx->H[i]);
      }
      abs_mmio_write32(kHmacBaseAddr + HMAC_MSG_LENGTH_LOWER_REG_OFFSET, ctx->lower);
      abs_mmio_write32(kHmacBaseAddr + HMAC_MSG_LENGTH_UPPER_REG_OFFSET, ctx->upper);
  
  } else {
    cmd_reg = bitfield_bit32_write(cmd_reg, HMAC_CMD_HASH_START_BIT, 1);
    ctx->hw_started = 1;
  }

  // Context is restored, now it's time to enable `sha_en`, see #23014.
  uint32_t cfg_reg = abs_mmio_read32(kHmacBaseAddr + HMAC_CFG_REG_OFFSET);
  cfg_reg = bitfield_bit32_write(cfg_reg, HMAC_CFG_SHA_EN_BIT, true);
  abs_mmio_write32(kHmacBaseAddr + HMAC_CFG_REG_OFFSET, cfg_reg);

  // Now we can finally write the command to the register.
  abs_mmio_write32(kHmacBaseAddr + HMAC_CMD_REG_OFFSET, cmd_reg);

}

/**
 * Save the context from HWIP into `ctx` object.
 *
 * This function should be called only after `stop` command is invoked and HWIP
 * confirms stopping through interrupt.
 */
static void save_context(hmac_ctx_t *ctx) {
  // TODO handle various block sizes

  // TODO handle other key sizes
  /*if (ctx->enable_hmac == kHardenedBoolTrue) {
    for(size_t i = 0; i < 8; i++) {
      ctx->key[i] = abs_mmio_read32(kHmacBaseAddr + HMAC_KEY_0_REG_OFFSET + 4*i);
    }
  }
  */

  // TODO: could be hardened.
  for(size_t i = 0; i < 8; i++) {
    ctx->H[i] = abs_mmio_read32(kHmacBaseAddr + HMAC_DIGEST_0_REG_OFFSET + 4*i);
  }
  ctx->lower = abs_mmio_read32(kHmacBaseAddr + HMAC_MSG_LENGTH_LOWER_REG_OFFSET);
  ctx->upper = abs_mmio_read32(kHmacBaseAddr + HMAC_MSG_LENGTH_UPPER_REG_OFFSET);
}

/**
 * Write given byte array into the `MSG_FIFO`. This function should only be
 * called when HWIP is already running and expecting further message bytes.
 */
static void write_to_msg_fifo(const uint8_t *msg, size_t msg_len) {
  for(size_t i = 0; i < msg_len; i++) {
    abs_mmio_write8(kHmacBaseAddr + HMAC_MSG_FIFO_REG_OFFSET, msg[i]);
  }
}

void hmac_init(hmac_ctx_t *ctx, const hmac_mode_t hmac_mode, const hmac_key_t *key) {

  // TODO Check SHA/HMAC before storing key.
  // Use hmac_mode instead
  if(key != NULL) {
    for(size_t i = 0; i < key->len / 4; i++) {
      ctx->key[i] = key->key[i];
    }
  }

  // TODO(#22731): implement other SHA2/HASH variants and remove hardcoded
  // values.
  ctx->digest_len = HMAC_CFG_DIGEST_SIZE_VALUE_SHA2_256;
  ctx->key_len = HMAC_CFG_KEY_LENGTH_VALUE_KEY_256;
  
  if (hmac_mode == kHmacModeHmac256) {
    ctx->enable_hmac = kHardenedBoolTrue;
  } else {
    ctx->enable_hmac = kHardenedBoolFalse;
  }

  // TODO: Consider zeroing state H, lower, upper, partial_block.
  
  // TODO: Better mubi type for hw_started.
  ctx->hw_started = 0;

  // TODO Consider init value for partial_block
  ctx->partial_block_len = 0;
}


void hmac_update(hmac_ctx_t *ctx, const uint8_t *data, size_t len) {
  
  // Check if we need to issue HW operation, i.e. whether we accumulated enough
  // message bits.

  // TODO Add other block size cases.
  size_t msg_block_len = kHmacSha256BlockBytes;

  // Skip if we do not have enough bytes to invoke HMAC.
  if (ctx->partial_block_len + len < msg_block_len) {
    memcpy(ctx->partial_block + ctx->partial_block_len, data, len);
    ctx->partial_block_len += len;
    return;
  }

  // `leftover` bits refers to the size of the next partial block, after we
  // handle the current partial block and the incoming message bytes.
  size_t leftover_len = (ctx->partial_block_len + len) % msg_block_len;

  // The previous caller should have left it clean, but it doesn't hurt to
  // clear again.
  hmac_hwip_clear();
  // If this is the first call, also load the key
  restore_context(ctx);

  // TODO check that it is OK to start with no message and then feed msg later.

  // Write `partial_block` to MSG_FIFO
  write_to_msg_fifo(ctx->partial_block, ctx->partial_block_len);
  //memcpy(kHmacBaseAddr + HMAC_MSG_FIFO_REG_OFFSET, partial_block,
  //      partial_block_len);

  // Keep writing incoming bytes
  // TODO: should we handle backpressure here?
  write_to_msg_fifo(data, len - leftover_len);
  //abs_mmio_write8(kHmacBaseAddr + HMAC_MSG_FIFO_REG_OFFSET,
  //                  data, len - leftover_len);

  // Time to tell HW to stop, because we do not have enough message bytes for
  // another round.
  uint32_t cmd_reg = bitfield_bit32_write(HMAC_CMD_REG_RESVAL, HMAC_CMD_HASH_STOP_BIT, 1);
  abs_mmio_write32(kHmacBaseAddr + HMAC_CMD_REG_OFFSET, cmd_reg);

  // Wait for HMAC to be done.
  wait_hmac_done();

  // Store context into `ctx`.
  save_context(ctx);

  // Write leftover bytes to `partial_block`, so that we feed them later.
  memcpy(ctx->partial_block, data + len - leftover_len, leftover_len);
  ctx->partial_block_len = leftover_len;

  // Clean up HWIP so it can be reused by other driver calls.
  hmac_hwip_clear();
}

void hmac_final(hmac_ctx_t *ctx, hmac_digest_t *digest) {
  
  // The previous caller should have left it clean, but it doesn't hurt to
  // clear again.
  hmac_hwip_clear();
  
  // TODO it should not be allowed to have 0 update calls?
  // check hw_initiated
  restore_context(ctx);

  // We need to feed the remaining bytes
  write_to_msg_fifo(ctx->partial_block, ctx->partial_block_len);

  // We are ready to issue process
  uint32_t cmd_reg = bitfield_bit32_write(HMAC_CMD_REG_RESVAL,
                                          HMAC_CMD_HASH_PROCESS_BIT, 1);
  abs_mmio_write32(kHmacBaseAddr + HMAC_CMD_REG_OFFSET, cmd_reg);
  wait_hmac_done();
  
  for (size_t i = 0; i < kHmacSha256DigestWords; i++) {
    digest->digest[i] = abs_mmio_read32(kHmacBaseAddr + HMAC_DIGEST_0_REG_OFFSET + 4*i);
  }

  // complete and wipe secrets
  hmac_hwip_clear();

  // TODO: destroy sensitive values in the ctx object
  // TODO: check if we had have errors
}
