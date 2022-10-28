// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/dif/dif_pinmux.h"
#include "sw/device/lib/dif/dif_pwrmgr.h"
#include "sw/device/lib/dif/dif_rstmgr.h"
#include "sw/device/lib/dif/dif_sysrst_ctrl.h"
#include "sw/device/lib/runtime/ibex.h"
#include "sw/device/lib/runtime/hart.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/pwrmgr_testutils.h"
#include "sw/device/lib/testing/rstmgr_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"

OTTF_DEFINE_TEST_CONFIG();

// This is updated by the sv component of the test
// Now `kTestPhase` is relocated to RamMain0
static volatile uint8_t kTestPhase = 0;

static dif_pwrmgr_t pwrmgr;
static dif_rstmgr_t rstmgr;
static dif_pinmux_t pinmux;
static dif_sysrst_ctrl_t sysrst_ctrl;

// This means 20 aon_clk ticks ~= 20 * 5 us = 100 us
static const uint16_t debounce_timer = 20;
uint8_t current_phase = 0;

enum {
  kNumMioInPads = 3,
  kNumMioOutPads = 1,
  kWaitWakeupTimeUsec = 500,
  // Make it slightly larger than debounce_timer
  kDebounceTimer = debounce_timer + 1,
};

const uint32_t kTestPhaseTimeoutUsec = 500;
enum {
  kTestPhaseInit = 0,
  kTestPhaseDriveZero = 1,
  kTestPhaseWaitNoWakeup = 2,
  kTestPhaseGlitchLidOpen = 3,
  kTestPhaseWaitWakeup = 4,
  kTestPhaseDone = 5,
};

static const dif_pinmux_index_t kPeripheralInputs[] = {
    kTopEarlgreyPinmuxPeripheralInSysrstCtrlAonPwrbIn,
    kTopEarlgreyPinmuxPeripheralInSysrstCtrlAonAcPresent,
    kTopEarlgreyPinmuxPeripheralInSysrstCtrlAonLidOpen,
};

static const dif_pinmux_index_t kInputPads[] = {
    kTopEarlgreyPinmuxInselIor13,
    kTopEarlgreyPinmuxInselIoc7,
    kTopEarlgreyPinmuxInselIoc9,
};

static const dif_pinmux_index_t kPeripheralOutputs[] = {
    kTopEarlgreyPinmuxOutselSysrstCtrlAonZ3Wakeup,
};

static const dif_pinmux_index_t kOutputPads[] = {
    kTopEarlgreyPinmuxMioOutIob7,
};

/**
 * Sets up the pinmux to assign input and output pads to the sysrst_ctrl
 * peripheral as required.
 */
static void pinmux_setup(void) {
  for (int i = 0; i < kNumMioInPads; ++i) {
    CHECK_DIF_OK(
        dif_pinmux_input_select(&pinmux, kPeripheralInputs[i], kInputPads[i]));
  }

  for (int i = 0; i < kNumMioOutPads; ++i) {
    CHECK_DIF_OK(dif_pinmux_output_select(&pinmux, kOutputPads[i],
                                          kPeripheralOutputs[i]));
  }
}

/**
 * Waits for `kTestPhase` variable to be changed by a backdoor overwrite
 * from the testbench in chip_sw_<testname>_vseq.sv. This will indicate that
 * the testbench is ready to proceed with the next phase of the test.
 */
static void wait_next_test_phase(void) {
  current_phase = kTestPhase;
  // Set WFI status for testbench synchronization
  // No WFI instruction is issued
  LOG_INFO("Prev test phase = %0d", kTestPhase);
  test_status_set(kTestStatusInWfi);
  test_status_set(kTestStatusInTest);
  // IBEX_SPIN_FOR(current_phase != kTestPhase, kTestPhaseTimeoutUsec);
  const ibex_timeout_t timeout_ = ibex_timeout_init(kTestPhaseTimeoutUsec);
  while (current_phase == kTestPhase) {
    CHECK(!ibex_timeout_check(&timeout_), "Timed out\n");
    //kTestPhase = 0xff;
  }

  LOG_INFO("Next test phase = %0d", kTestPhase);
}

/**
 * Configure *_debounce_ctl and then enable ULP wakeup.
 */
static void configure_wakeup(void) {
  dif_sysrst_ctrl_ulp_wakeup_config_t wakeup_config;

  // Keep toggle disabled when writing debounce configuration
  wakeup_config.enabled = kDifToggleDisabled;
  wakeup_config.ac_power_debounce_time_threshold = debounce_timer;
  wakeup_config.lid_open_debounce_time_threshold = debounce_timer;
  wakeup_config.power_button_debounce_time_threshold = debounce_timer;

  CHECK_DIF_OK(
      dif_sysrst_ctrl_ulp_wakeup_configure(&sysrst_ctrl, wakeup_config));

  CHECK_DIF_OK(
      dif_sysrst_ctrl_ulp_wakeup_set_enabled(&sysrst_ctrl, kDifToggleEnabled));
}

static void go_to_sleep(void) {
  // Wakeup source is from sysrst_ctrl (source one).
  rstmgr_testutils_pre_reset(&rstmgr);
  pwrmgr_testutils_enable_low_power(&pwrmgr, 63, //kDifPwrmgrWakeupRequestSourceOne,
                                    kDifPwrmgrDomainOptionMainPowerInLowPower);
  // Enable intr for shallow sleep
  // I guess this interrupt won't reach ibex because we didnt set up PLIC
  CHECK_DIF_OK(dif_pwrmgr_irq_set_enabled(&pwrmgr, kDifPwrmgrIrqWakeup, kDifToggleEnabled));
  LOG_INFO("Going to sleep.");
  test_status_set(kTestStatusInWfi);
  wait_for_interrupt();
}

static void check_wakeup_reason(void) {
  dif_rstmgr_reset_info_bitfield_t rst_info;
  rst_info = rstmgr_testutils_reason_get();
  rstmgr_testutils_reason_clear();

  CHECK(rst_info == kDifRstmgrResetInfoLowPowerExit, "Wrong reset reason %02X",
        rst_info);
}

static dif_rstmgr_reset_info_bitfield_t get_wakeup_reason() {
  dif_rstmgr_reset_info_bitfield_t rst_info;
  rst_info = rstmgr_testutils_reason_get();
  rstmgr_testutils_reason_clear();
  return rst_info;
}

static bool has_wakeup_happened(void) {
  bool wakeup_detected;
  CHECK_DIF_OK(
      dif_sysrst_ctrl_ulp_wakeup_get_status(&sysrst_ctrl, &wakeup_detected));
  return wakeup_detected;
}

bool test_main(void) {
  CHECK_DIF_OK(dif_sysrst_ctrl_init(
      mmio_region_from_addr(TOP_EARLGREY_SYSRST_CTRL_AON_BASE_ADDR),
      &sysrst_ctrl));
  CHECK_DIF_OK(dif_pinmux_init(
      mmio_region_from_addr(TOP_EARLGREY_PINMUX_AON_BASE_ADDR), &pinmux));
  CHECK_DIF_OK(dif_pwrmgr_init(
      mmio_region_from_addr(TOP_EARLGREY_PWRMGR_AON_BASE_ADDR), &pwrmgr));
  CHECK_DIF_OK(dif_rstmgr_init(
      mmio_region_from_addr(TOP_EARLGREY_RSTMGR_AON_BASE_ADDR), &rstmgr));


  dif_rstmgr_reset_info_bitfield_t wakeup_reason = get_wakeup_reason();
  LOG_INFO("wk reason = %d", wakeup_reason);
  CHECK(wakeup_reason == kDifRstmgrResetInfoPor);
  LOG_INFO("Test starting.");

  pinmux_setup();
  configure_wakeup();
  LOG_INFO("sysrst_ctrl wakeup enabled.");
  

  // Make sure we wait *at least* `kWaitWakeupTimeUsec`
  busy_spin_micros(30);
  CHECK(!has_wakeup_happened());
  LOG_INFO("No wakeup yet.");
  test_status_set(kTestStatusInWfi);
  test_status_set(kTestStatusInTest);

  go_to_sleep();
  CHECK(get_wakeup_reason() == kDifRstmgrResetInfoLowPowerExit);

  LOG_INFO("SW has waken up.");
  test_status_set(kTestStatusInWfi);
  test_status_set(kTestStatusInTest);

  // Sort of redundant secondary check
  CHECK(has_wakeup_happened());
  //check_wakeup_reason();
  LOG_INFO("Test done.");


  /*
  while (kTestPhase < kTestPhaseDone) {
    switch (kTestPhase) {
      case kTestPhaseInit:
        break;
      case kTestPhaseDriveZero:
        LOG_INFO("kTestPhaseDriveZero");
        break;
      case kTestPhaseWaitNoWakeup:
        CHECK(!has_wakeup_happened());
        LOG_INFO("kTestPhaseWaitNoWakeup");
        go_to_sleep();
        check_wakeup_reason();
        break;
      case kTestPhaseGlitchLidOpen:
        LOG_INFO("kTestPhaseGlitchLidOpen");
        break;
      case kTestPhaseWaitWakeup:
        CHECK(has_wakeup_happened());
        LOG_INFO("kTestPhaseWaitWakeup");
        break;
      default:
        LOG_ERROR("Unexpected test phase : %d", kTestPhase);
        LOG_INFO("END");
        break;
    }
    wait_next_test_phase();
  }
  */

  return true;
}
