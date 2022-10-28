// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

class chip_sw_sysrst_ctrl_ulp_z3_wakeup_vseq extends chip_sw_base_vseq;
  import dv_utils_pkg::*;
  `uvm_object_utils(chip_sw_sysrst_ctrl_ulp_z3_wakeup_vseq)
  `uvm_object_new

  //localparam string PAD_PWRB_PATH      = "tb.dut.IOR13";
  //localparam string PAD_ACPRESENT_PATH = "tb.dut.IOC7";
  //localparam string PAD_LIDOPEN_PATH   = "tb.dut.IOC9";
  //localparam string PAD_Z3WAKEUP_PATH  = "tb.dut.IOB7";

  // The value of configured debounce value
  localparam uint DEBOUNCE_SW_VALUE = 20;

  typedef enum bit [7:0] {
    PHASE_INIT                  = 0,
    PHASE_DRIVE_ZERO            = 1,
    PHASE_WAIT_NO_WAKEUP        = 2,
    PHASE_GLITCH_LID_OPEN       = 3,
    PHASE_WAIT_WAKEUP           = 4,
    PHASE_DONE                  = 5
  } test_phases_e;

  virtual task pre_start();
    super.pre_start();
    // Initialize the pad input to 0 to avoid having X values in the initial test phase.
    cfg.chip_vif.pwrb_in_if.pins_pd[0] = 1;
    cfg.chip_vif.sysrst_ctrl_if.pins_pd[4] = 1;
    cfg.chip_vif.sysrst_ctrl_if.pins_pd[5] = 1;
    // Same for output
    //cfg.chip_vif.pinmux_wkup_if.pins_pd[0] = 1;
    //cfg.chip_vif.sysrst_ctrl_if.pins_pd[2] = 1;
  endtask

  virtual function void drive_zero_pads();
    //`DV_CHECK(uvm_hdl_force(PAD_PWRB_PATH, 1'b0));
    cfg.chip_vif.pwrb_in_if.drive_pin(0, 1'b0);
    //`DV_CHECK(uvm_hdl_force(PAD_ACPRESENT_PATH, 1'b0));
    cfg.chip_vif.sysrst_ctrl_if.drive_pin(4, 1'b0);
    //`DV_CHECK(uvm_hdl_force(PAD_LIDOPEN_PATH, 1'b0));
    cfg.chip_vif.sysrst_ctrl_if.drive_pin(5, 1'b0);
  endfunction

  virtual task glitch_lid_open();
    uint glitch_loop_cnt = $urandom_range(1, DEBOUNCE_SW_VALUE - 1);
    bit glitchy_bit = 1'b1;
    // The following loop ends before the second sampling of debounce happens
    for (int i = 0; i < glitch_loop_cnt ; i++) begin
      //`DV_CHECK(uvm_hdl_force(PAD_LIDOPEN_PATH, glitchy_bit));
      cfg.chip_vif.sysrst_ctrl_if.drive_pin(5, glitchy_bit);
      cfg.chip_vif.aon_clk_por_rst_if.wait_clks(1);
      glitchy_bit = ~glitchy_bit;
    end
    //`DV_CHECK(uvm_hdl_force(PAD_LIDOPEN_PATH, 1'b1));
    cfg.chip_vif.sysrst_ctrl_if.drive_pin(5, 1'b1);
  endtask

  /*
  virtual function void write_test_phase(test_phases_e phase);
    bit [7:0] test_phase[1];
    test_phase[0] = phase;
    sw_symbol_backdoor_overwrite("kTestPhase", test_phase);
    test_phase[0] = PHASE_CACHE_INVALIDATE;
    sw_symbol_backdoor_overwrite("kTestPhase", );
  endfunction
  */

  virtual function void write_test_phase(input test_phases_e phase);
    sw_symbol_backdoor_overwrite("kTestPhase", {<<8{phase}});
  endfunction


  virtual function check_wakeup_pin();
    logic wakeup_result;
    //`DV_CHECK(uvm_hdl_read(PAD_Z3WAKEUP_PATH, wakeup_result));
    //wakeup_result = cfg.chip_vif.sysrst_ctrl_if.sample_pin(2);
    wakeup_result = cfg.chip_vif.pinmux_wkup_if.sample_pin(0);
    `DV_CHECK_EQ_FATAL(wakeup_result, 1'b1);
  endfunction

  virtual task wait_wakeup_time();
    // Wait until we are sure that we passed the second sampling of debounce logic
    cfg.chip_vif.aon_clk_por_rst_if.wait_clks(DEBOUNCE_SW_VALUE);
  endtask

  virtual task sync_with_sw();
    `DV_WAIT(cfg.sw_test_status_vif.sw_test_status == SwTestStatusInWfi)
    `DV_WAIT(cfg.sw_test_status_vif.sw_test_status == SwTestStatusInTest)
  endtask

  virtual task body();
    super.body();

    // TODO(lowRISC/opentitan:#13373): Revisit pad assignments.
    // pinmux_wkup_vif (at Iob7) is re-used for PinZ3WakeupOut
    // due to lack of unused pins. Disable the default drive
    // to this pin.
    cfg.chip_vif.pinmux_wkup_if.drive_en_pin(0, 0);

    drive_zero_pads();

    //`DV_WAIT(cfg.sw_logger_vif.printed_log == "sysrst_ctrl wakeup enabled.")

    //`DV_WAIT(cfg.sw_logger_vif.printed_log == "No wakeup yet.")
    sync_with_sw();


    `DV_WAIT(cfg.sw_test_status_vif.sw_test_status == SwTestStatusInWfi)

    glitch_lid_open();
    wait_wakeup_time();
    sync_with_sw();

    //`DV_WAIT(cfg.sw_logger_vif.printed_log == "SW has waken up.")
    //check_wakeup_pin();

    /*
    drive_zero_pads();
    write_test_phase(PHASE_DRIVE_ZERO);
    sync_with_sw();

    wait_wakeup_time();
    write_test_phase(PHASE_WAIT_NO_WAKEUP);
    // Skip sync_with_sw, because SW starts sleeping after Wfi
    `DV_WAIT(cfg.sw_test_status_vif.sw_test_status == SwTestStatusInWfi)

    glitch_lid_open();
    write_test_phase(PHASE_GLITCH_LID_OPEN);
    sync_with_sw();

    wait_wakeup_time();
    write_test_phase(PHASE_WAIT_WAKEUP);
    check_wakeup_pin();
    sync_with_sw();

    write_test_phase(PHASE_DONE);
    */
  endtask

endclass : chip_sw_sysrst_ctrl_ulp_z3_wakeup_vseq
