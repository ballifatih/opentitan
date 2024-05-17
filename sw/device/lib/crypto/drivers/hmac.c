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
  // Restore CFG register from `ctx`.
  abs_mmio_write32(kHmacBaseAddr + HMAC_CFG_REG_OFFSET, ctx->cfg_reg);

  uint32_t cmd_reg = HMAC_CMD_REG_RESVAL;
  // Decide if we need to invoke `start` or `continue` command.

  // Write to KEY registers for HMAC operations. If the operation is SHA-2,
  // `key_len` is set to 0 during `ctx` initialization.
  for(size_t i = 0; i < ctx->key_len; i++) {
    abs_mmio_write32(kHmacBaseAddr + HMAC_KEY_0_REG_OFFSET + 4*i, ctx->key[i]);
  }

  if(ctx->hw_started) {
      cmd_reg = bitfield_bit32_write(cmd_reg, HMAC_CMD_HASH_CONTINUE_BIT, 1);

      // TODO: Remove hard coded digest len.
      // TODO: Could be hardened for HMAC.
      for(size_t i = 0; i < kHmacMaxDigestWords; i++) {
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

  // TODO: could be hardened.
  for(size_t i = 0; i < kHmacMaxDigestWords; i++) {
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

OT_WARN_UNUSED_RESULT
status_t hmac_init(hmac_ctx_t *ctx, const hmac_mode_t hmac_mode, const hmac_key_t *key) {

  if (ctx == NULL) {
    return OTCRYPTO_BAD_ARGS;
  }

  // TODO zeroize all fields of ctx
  //memset(ctx, 0, sizeof(hmac_ctx_t));

  // Prepare cfg_reg in context.
  ctx->cfg_reg = HMAC_CFG_REG_RESVAL;
  // The endianness is fixed at driver level and not exposed to the caller.
  // Digest should be big-endian to match the SHA-256 specification.
  ctx->cfg_reg = bitfield_bit32_write(ctx->cfg_reg, HMAC_CFG_DIGEST_SWAP_BIT, true);
  // Message should be little-endian to match Ibex's endianness.
  ctx->cfg_reg = bitfield_bit32_write(ctx->cfg_reg, HMAC_CFG_ENDIAN_SWAP_BIT, false);

  // We need to keep `sha_en` low until context is restored, see #23014.
  ctx->cfg_reg = bitfield_bit32_write(ctx->cfg_reg, HMAC_CFG_SHA_EN_BIT, false);

  switch (hmac_mode) {
    case kHmacModeSha256:
      ctx->cfg_reg = bitfield_field32_write(ctx->cfg_reg, HMAC_CFG_DIGEST_SIZE_FIELD,
                               HMAC_CFG_DIGEST_SIZE_VALUE_SHA2_256);
      ctx->cfg_reg = bitfield_bit32_write(ctx->cfg_reg, HMAC_CFG_HMAC_EN_BIT, false);
      ctx-> msg_block_len = 512 / 8;
      ctx-> digest_len = 256 / 8;
      break;
    case kHmacModeSha384:
      ctx->cfg_reg = bitfield_field32_write(ctx->cfg_reg, HMAC_CFG_DIGEST_SIZE_FIELD,
                               HMAC_CFG_DIGEST_SIZE_VALUE_SHA2_384);
      ctx->cfg_reg = bitfield_bit32_write(ctx->cfg_reg, HMAC_CFG_HMAC_EN_BIT, false);
      ctx-> msg_block_len = 1024 / 8;
      ctx-> digest_len = 384 / 8;
      break;
    case kHmacModeSha512:
      ctx->cfg_reg = bitfield_field32_write(ctx->cfg_reg, HMAC_CFG_DIGEST_SIZE_FIELD,
                              HMAC_CFG_DIGEST_SIZE_VALUE_SHA2_512);
      ctx->cfg_reg = bitfield_bit32_write(ctx->cfg_reg, HMAC_CFG_HMAC_EN_BIT, false);
      ctx-> msg_block_len = 1024 / 8;
      ctx-> digest_len = 512 / 8;
      break;
    case kHmacModeHmac256:
      ctx->cfg_reg = bitfield_field32_write(ctx->cfg_reg, HMAC_CFG_DIGEST_SIZE_FIELD,
                               HMAC_CFG_DIGEST_SIZE_VALUE_SHA2_256);
      ctx->cfg_reg = bitfield_bit32_write(ctx->cfg_reg, HMAC_CFG_HMAC_EN_BIT, true);
      ctx-> msg_block_len = 512 / 8;
      ctx-> digest_len = 256 / 8;
      break;
    case kHmacModeHmac384:
      ctx->cfg_reg = bitfield_field32_write(ctx->cfg_reg, HMAC_CFG_DIGEST_SIZE_FIELD,
                               HMAC_CFG_DIGEST_SIZE_VALUE_SHA2_384);
      ctx->cfg_reg = bitfield_bit32_write(ctx->cfg_reg, HMAC_CFG_HMAC_EN_BIT, true);
      ctx-> msg_block_len = 1024 / 8;
      ctx-> digest_len = 384 / 8;
      break;
    case kHmacModeHmac512:
      ctx->cfg_reg = bitfield_field32_write(ctx->cfg_reg, HMAC_CFG_DIGEST_SIZE_FIELD,
                               HMAC_CFG_DIGEST_SIZE_VALUE_SHA2_512);
      ctx->cfg_reg = bitfield_bit32_write(ctx->cfg_reg, HMAC_CFG_HMAC_EN_BIT, true);
      ctx-> msg_block_len = 1024 / 8;
      ctx-> digest_len = 512 / 8;
      break;
    default:
      return OTCRYPTO_BAD_ARGS;
  }
  
  if (hmac_mode == kHmacModeHmac256 || hmac_mode == kHmacModeHmac384 ||
      hmac_mode == kHmacModeHmac512) {
    if (key == NULL) {
      return OTCRYPTO_BAD_ARGS;
    }
    switch (key->len) {
      case 128 / 8:
        ctx->cfg_reg = bitfield_field32_write(ctx->cfg_reg, HMAC_CFG_KEY_LENGTH_FIELD, HMAC_CFG_KEY_LENGTH_VALUE_KEY_128);
        break;
      case 256 / 8:
        ctx->cfg_reg = bitfield_field32_write(ctx->cfg_reg, HMAC_CFG_KEY_LENGTH_FIELD, HMAC_CFG_KEY_LENGTH_VALUE_KEY_256);
        break;
      case 384 / 8:
        ctx->cfg_reg = bitfield_field32_write(ctx->cfg_reg, HMAC_CFG_KEY_LENGTH_FIELD, HMAC_CFG_KEY_LENGTH_VALUE_KEY_384);
        break;
      case 512 / 8:
        ctx->cfg_reg = bitfield_field32_write(ctx->cfg_reg, HMAC_CFG_KEY_LENGTH_FIELD, HMAC_CFG_KEY_LENGTH_VALUE_KEY_512);
        break;
      case 1024 / 8:
        ctx->cfg_reg = bitfield_field32_write(ctx->cfg_reg, HMAC_CFG_KEY_LENGTH_FIELD, HMAC_CFG_KEY_LENGTH_VALUE_KEY_1024);
        break;
      default:
        return OTCRYPTO_BAD_ARGS;
    }
    // TODO: validate key->len, i.e. supported by HW.
    ctx->key_len = key->len / sizeof(uint32_t);
    for(size_t i = 0; i < ctx->key_len; i++) {
      ctx->key[i] = key->key[i];
    }
  } else {
    // Ensure that `key` is NULL for hashing operations.
    if (key != NULL) {
      return OTCRYPTO_BAD_ARGS;
    }
    // Set `key_len` to 0, so that it is clear this is hash operation.
    ctx->key_len = 0;
  }
  
  // TODO: Better mubi type for hw_started.
  ctx->hw_started = 0;

  // TODO Consider init value for partial_block
  ctx->partial_block_len = 0;
  
  return OTCRYPTO_OK;
}


void hmac_update(hmac_ctx_t *ctx, const uint8_t *data, size_t len) {
  
  // Check if we need to issue HW operation, i.e. whether we accumulated enough
  // message bits.

  // Skip if we do not have enough bytes to invoke HMAC.
  if (ctx->partial_block_len + len < ctx->msg_block_len) {
    memcpy(ctx->partial_block + ctx->partial_block_len, data, len);
    ctx->partial_block_len += len;
    return;
  }

  // `leftover` bits refers to the size of the next partial block, after we
  // handle the current partial block and the incoming message bytes.
  size_t leftover_len = (ctx->partial_block_len + len) % ctx->msg_block_len;

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

OT_WARN_UNUSED_RESULT
status_t hmac_final(hmac_ctx_t *ctx, hmac_digest_t *digest) {
  
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
  
  // TODO check digest_len is compatible with ctx.
  if(ctx->digest_len != digest->len) {
    return OTCRYPTO_BAD_ARGS;
  }

  for (size_t i = 0; i < digest->len / sizeof(uint32_t); i++) {
    digest->digest[i] = abs_mmio_read32(kHmacBaseAddr + HMAC_DIGEST_0_REG_OFFSET + 4*i);
  }

  // complete and wipe secrets
  hmac_hwip_clear();

  // TODO: destroy sensitive values in the ctx object
  // TODO: check if we had have errors
  return OTCRYPTO_OK;
}
