// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Base class providing common methods required for DMA testing
class dma_base_vseq extends cip_base_vseq #(
  .RAL_T              (dma_reg_block),
  .CFG_T              (dma_env_cfg),
  .COV_T              (dma_env_cov),
  .VIRTUAL_SEQUENCER_T(dma_virtual_sequencer)
);

  `uvm_object_utils(dma_base_vseq)

  bit sim_fatal_exit_on_dma_error = 1;

  // Valid address space ID conbinations
  addr_space_id_t valid_combinations[] = '{
    '{OtInternalAddr, SocControlAddr},
    '{OtInternalAddr, SocControlAddr},
    // TODO remove once SYS support is enabled'{OtInternalAddr, SocSystemAddr},
    '{OtInternalAddr, OtExtFlashAddr},
    '{SocControlAddr, OtInternalAddr},
    '{SocControlAddr, OtInternalAddr},
    // TODO remove once SYS support is enabled '{SocSystemAddr, OtInternalAddr},
    '{OtExtFlashAddr, OtInternalAddr},
    '{OtInternalAddr, OtInternalAddr}
  };
  // response sequences
  dma_pull_seq #(.AddrWidth(HOST_ADDR_WIDTH)) seq_host;
  dma_pull_seq #(.AddrWidth(CTN_ADDR_WIDTH)) seq_ctn;
  dma_pull_seq #(.AddrWidth(SYS_ADDR_WIDTH)) seq_sys;

  // DMA configuration item
  dma_seq_item dma_config;

  // Event triggers
  event e_busy;
  event e_complete;
  event e_aborted;
  event e_errored;
  event e_sha2_digest_valid;

  function new (string name = "");
    super.new(name);
    dma_config = dma_seq_item::type_id::create("dma_config");
    // response sequences
    seq_ctn = dma_pull_seq #(.AddrWidth(CTN_ADDR_WIDTH))::type_id::create("seq_ctn");
    seq_host = dma_pull_seq #(.AddrWidth(HOST_ADDR_WIDTH))::type_id::create("seq_host");
    seq_sys  = dma_pull_seq #(.AddrWidth(SYS_ADDR_WIDTH))::type_id::create("seq_sys");
    // Create memory models
    seq_host.fifo = dma_handshake_mode_fifo#(
                                .AddrWidth(HOST_ADDR_WIDTH))::type_id::create("fifo_host");
    seq_ctn.fifo = dma_handshake_mode_fifo#(
                                .AddrWidth(CTN_ADDR_WIDTH))::type_id::create("fifo_ctn");
    seq_sys.fifo = dma_handshake_mode_fifo#(
                                .AddrWidth(SYS_ADDR_WIDTH))::type_id::create("fifo_sys");
    seq_host.mem = mem_model#(.AddrWidth(HOST_ADDR_WIDTH),
                                .DataWidth(HOST_DATA_WIDTH))::type_id::create("mem_host");
    seq_ctn.mem = mem_model#(.AddrWidth(CTN_ADDR_WIDTH),
                                .DataWidth(CTN_DATA_WIDTH))::type_id::create("mem_ctn");
    seq_sys.mem = mem_model#(.AddrWidth(SYS_ADDR_WIDTH),
                               .DataWidth(SYS_DATA_WIDTH))::type_id::create("mem_sys");
  endfunction: new

  function void init_model();
    // Assign mem_model instance handle to config object
    cfg.mem_ctn = seq_ctn.mem;
    cfg.mem_host = seq_host.mem;
    cfg.mem_sys = seq_sys.mem;
    // Assign dma_handshake_mode_fifo instance handle to config object
    cfg.fifo_ctn = seq_ctn.fifo;
    cfg.fifo_host = seq_host.fifo;
    cfg.fifo_sys = seq_sys.fifo;
    // Initialize memory
    cfg.mem_host.init();
    cfg.mem_ctn.init();
    cfg.mem_sys.init();
    cfg.fifo_host.init();
    cfg.fifo_ctn.init();
    cfg.fifo_sys.init();
  endfunction

  // randomise data in source memory model based on source address space id setting
  function void randomise_asid_mem(asid_encoding_e asid,
                                   bit [63:0] start_addr,
                                   bit [31:0] total_data_size);
    // Address generated by DMA is always 4B aligned - refer #338
    bit [63:0] end_addr = start_addr + total_data_size;
    // Actual data size for the operation
    bit [31:0] data_size = total_data_size;
    // Add extra bytes if Start address is unaligned
    data_size += start_addr[1:0];
    // Add extra bytes if End address is unaligned
    data_size += 4 - end_addr[1:0];
    if (total_data_size < data_size) begin
      `uvm_info(`gfn, $sformatf("total_data_size = %0d B effective data_size = %0d B",
                                total_data_size, data_size), UVM_HIGH)
    end
    case (asid)
      OtInternalAddr: begin
        cfg.mem_host.randomise_mem({start_addr[63:2],2'd0}, data_size);
      end
      SocControlAddr,
      OtExtFlashAddr: begin
        cfg.mem_ctn.randomise_mem({start_addr[63:2],2'd0}, data_size);
      end
      SocSystemAddr: begin
        cfg.mem_sys.randomise_mem({start_addr[63:2],2'd0}, data_size);
      end
      default: begin
        `uvm_error(`gfn, $sformatf("Unsupported Address space ID %d", asid))
      end
    endcase
  endfunction

  // Function to randomise FIFO data
  function void randomise_fifo_data(asid_encoding_e asid, bit [31:0] total_data_size);
    case (asid)
      OtInternalAddr: begin
        cfg.fifo_host.randomise_data(total_data_size);
      end
      SocControlAddr, OtExtFlashAddr: begin
        cfg.fifo_ctn.randomise_data(total_data_size);
      end
      SocSystemAddr: begin
        cfg.fifo_sys.randomise_data(total_data_size);
      end
      default: begin
        `uvm_error(`gfn, $sformatf("Unsupported Address space ID %d", asid))
      end
    endcase
  endfunction

  // Function to set dma_handshake_mode_fifo mode settings
  function void set_model_fifo_mode(asid_encoding_e asid,
                                    bit [63:0] start_addr = '0,
                                    bit [31:0] total_data_size);
    start_addr[1:0] = 2'd0; // Address generated by DMA is 4B aligned
    case (asid)
      OtInternalAddr: begin
        cfg.fifo_host.enable_fifo(.fifo_base (start_addr),
                             .max_size (total_data_size));
      end
      SocControlAddr, OtExtFlashAddr: begin
        cfg.fifo_ctn.enable_fifo(.fifo_base (start_addr),
                            .max_size (total_data_size));
      end
      SocSystemAddr: begin
        cfg.fifo_sys.enable_fifo(.fifo_base (start_addr),
                            .max_size (total_data_size));
      end
      default: begin
        `uvm_error(`gfn, $sformatf("Unsupported Address space ID %d", asid))
      end
    endcase
  endfunction

  // Function to enable FIFO if handshake mode is enabled
  // else randomise read data in mem_model or FIFO instance
  function void configure_mem_model(ref dma_seq_item dma_config);
    // Configure Source model
    if (dma_config.get_read_fifo_en()) begin
      // Enable read FIFO mode in models
      set_model_fifo_mode(dma_config.src_asid, dma_config.src_addr,
                          dma_config.total_transfer_size);
      // Randomise FIFO data
      randomise_fifo_data(dma_config.src_asid, dma_config.total_transfer_size);
    end else begin
      // Randomise mem_model data
      randomise_asid_mem(dma_config.src_asid, dma_config.src_addr,
                         dma_config.total_transfer_size);
    end

    // Configure Destination model
    if (dma_config.get_write_fifo_en()) begin
      // Enable write FIFO mode in models
      set_model_fifo_mode(dma_config.dst_asid, dma_config.dst_addr,
                          dma_config.total_transfer_size);
    end
  endfunction

  // Set hardware handshake interrupt bits based on randomized class item
  function void set_hardware_handshake_intr(
    bit [dma_reg_pkg::NumIntClearSources-1:0] handshake_value);
    cfg.dma_vif.handshake_i = handshake_value;
  endfunction

  function void release_hardware_handshake_intr();
    cfg.dma_vif.handshake_i = '0;
  endfunction

  // Task: Write to Source Address CSR
  task set_source_address(bit [63:0] source_address);
    `uvm_info(`gfn, $sformatf("DMA: Source Address = 0x%016h", source_address), UVM_HIGH)
    csr_wr(ral.source_address_lo, source_address[31:0]);
    csr_wr(ral.source_address_hi, source_address[63:32]);
  endtask: set_source_address

  // Task: Write to Destination Address CSR
  task set_destination_address(bit [63:0] destination_address);
    csr_wr(ral.destination_address_lo, destination_address[31:0]);
    csr_wr(ral.destination_address_hi, destination_address[63:32]);
    `uvm_info(`gfn, $sformatf("DMA: Destination Address = 0x%016h", destination_address), UVM_HIGH)
  endtask: set_destination_address

  task set_destination_address_range(bit[63:0] almost_limit,
                                     bit[63:0] limit);
    csr_wr(ral.destination_address_limit_lo, limit[31:0]);
    csr_wr(ral.destination_address_limit_hi, limit[63:32]);
    `uvm_info(`gfn, $sformatf("DMA: Destination Limit = 0x%016h", limit), UVM_HIGH)
    csr_wr(ral.destination_address_almost_limit_lo, almost_limit[31:0]);
    csr_wr(ral.destination_address_almost_limit_hi, almost_limit[63:32]);
    `uvm_info(`gfn, $sformatf("DMA: Destination Almost Limit = 0x%016h", almost_limit), UVM_HIGH)
  endtask: set_destination_address_range

  // Task: Set DMA Enabled Memory base and limit
  task set_dma_enabled_memory_range(bit [32:0] base, bit [31:0] limit, mubi4_t lock);
    csr_wr(ral.enabled_memory_range_base, base);
    `uvm_info(`gfn, $sformatf("DMA: DMA Enabled Memory base = %0x08h", base), UVM_HIGH)
    csr_wr(ral.enabled_memory_range_limit, limit);
    `uvm_info(`gfn, $sformatf("DMA: DMA Enabled Memory limit = %0x08h", limit), UVM_HIGH)
    csr_wr(ral.range_valid, 1'b1);
    `uvm_info(`gfn, "DMA: DMA Enabled Memory Range is valid", UVM_HIGH)
    if (lock != MuBi4True) begin
      csr_wr(ral.range_regwen, int'(lock));
      `uvm_info(`gfn, $sformatf("DMA: DMA Enabled Memory lock = %s", lock.name()), UVM_HIGH)
    end
  endtask: set_dma_enabled_memory_range

  // Task: Write to Source and Destination Address Space ID (ASID)
  task set_address_space_id(asid_encoding_e src_asid, asid_encoding_e dst_asid);
    ral.address_space_id.source_asid.set(int'(src_asid));
    ral.address_space_id.destination_asid.set(int'(dst_asid));
    csr_update(.csr(ral.address_space_id));
    `uvm_info(`gfn, $sformatf("DMA: Source ASID = %d", src_asid), UVM_HIGH)
    `uvm_info(`gfn, $sformatf("DMA: Destination ASID = %d", dst_asid), UVM_HIGH)
  endtask: set_address_space_id

  // Task: Set number of bytes to transfer
  task set_total_size(bit [31:0] total_data_size);
    csr_wr(ral.total_data_size, total_data_size);
    `uvm_info(`gfn, $sformatf("DMA: Total Data Size = %d", total_data_size), UVM_HIGH)
  endtask: set_total_size

  // Task: Set number of bytes per chunk to transfer
  task set_chunk_data_size(bit [31:0] chunk_data_size);
    csr_wr(ral.chunk_data_size, chunk_data_size);
    `uvm_info(`gfn, $sformatf("DMA: Chunk Data Size = %d", chunk_data_size), UVM_HIGH)
  endtask: set_chunk_data_size

  // Task: Set Byte size of each transfer (0:1B, 1:2B, 2:3B, 3:4B)
  task set_transfer_width(dma_transfer_width_e transfer_width);
    csr_wr(ral.transfer_width, transfer_width);
    `uvm_info(`gfn, $sformatf("DMA: Transfer Byte Size = %d",
                              transfer_width.name()), UVM_HIGH)
  endtask: set_transfer_width

  // Task: Set handshake interrupt register
  task set_handshake_int_regs(ref dma_seq_item dma_config);
    `uvm_info(`gfn, "Set DMA Handshake mode interrupt registers", UVM_HIGH)
    csr_wr(ral.clear_int_src, dma_config.clear_int_src);
    csr_wr(ral.clear_int_bus, dma_config.clear_int_bus);
    foreach (dma_config.int_src_addr[i]) begin
      csr_wr(ral.int_source_addr[i], dma_config.int_src_addr[i]);
      csr_wr(ral.int_source_wr_val[i], dma_config.int_src_wr_val[i]);
    end
    ral.handshake_interrupt_enable.set(dma_config.handshake_intr_en);
    csr_update(ral.handshake_interrupt_enable);
  endtask: set_handshake_int_regs

  // Task: Run above configurations common to both Generic and Handshake Mode of operations
  task run_common_config(ref dma_seq_item dma_config);
    `uvm_info(`gfn, "DMA: Start Common Configuration", UVM_HIGH)
    set_source_address(dma_config.src_addr);
    set_destination_address(dma_config.dst_addr);
    set_destination_address_range(dma_config.mem_buffer_almost_limit,
                                  dma_config.mem_buffer_limit);
    set_address_space_id(dma_config.src_asid, dma_config.dst_asid);
    set_total_size(dma_config.total_transfer_size);
    set_chunk_data_size(dma_config.total_transfer_size);  // TODO: same config for now
    set_transfer_width(dma_config.per_transfer_width);
    configure_mem_model(dma_config);
    set_handshake_int_regs(dma_config);
    set_dma_enabled_memory_range(dma_config.mem_range_base,
                                 dma_config.mem_range_limit,
                                 dma_config.mem_range_lock);
  endtask: run_common_config

  // Task: Enable Interrupt
  task enable_interrupt();
    `uvm_info(`gfn, "DMA: Assert Interrupt Enable", UVM_HIGH)
    csr_wr(ral.intr_enable, (1 << ral.intr_enable.get_n_bits()) - 1);
  endtask: enable_interrupt

  // Task: Enable Handshake Interrupt Enable
  task enable_handshake_interrupt();
    `uvm_info(`gfn, "DMA: Assert Interrupt Enable", UVM_HIGH)
    csr_wr(ral.handshake_interrupt_enable, 32'd1);
  endtask: enable_handshake_interrupt

  function void set_seq_fifo_read_mode(asid_encoding_e asid, bit read_fifo_en);
    case (asid)
      OtInternalAddr: begin
        seq_host.read_fifo_en = read_fifo_en;
        `uvm_info(`gfn, $sformatf("set host read_fifo_en = %0b", read_fifo_en), UVM_HIGH)
      end
      SocControlAddr, OtExtFlashAddr: begin
        seq_ctn.read_fifo_en = read_fifo_en;
        `uvm_info(`gfn, $sformatf("set ctn read_fifo_en = %0b", read_fifo_en), UVM_HIGH)
      end
      SocSystemAddr: begin
        seq_sys.read_fifo_en = read_fifo_en;
        `uvm_info(`gfn, $sformatf("set sys read_fifo_en = %0b", read_fifo_en), UVM_HIGH)
      end
      default: begin
        `uvm_error(`gfn, $sformatf("Unsupported Address space ID %d", asid))
      end
    endcase
  endfunction

  function void set_seq_fifo_write_mode(asid_encoding_e asid, bit write_fifo_en);
    case (asid)
      OtInternalAddr: begin
        seq_host.write_fifo_en = write_fifo_en;
        `uvm_info(`gfn, $sformatf("set host write_fifo_en = %0b", write_fifo_en), UVM_HIGH)
      end
      SocControlAddr, OtExtFlashAddr: begin
        seq_ctn.write_fifo_en = write_fifo_en;
        `uvm_info(`gfn, $sformatf("set ctn write_fifo_en = %0b", write_fifo_en), UVM_HIGH)
      end
      SocSystemAddr: begin
        seq_sys.write_fifo_en = write_fifo_en;
        `uvm_info(`gfn, $sformatf("set sys write_fifo_en = %0b", write_fifo_en), UVM_HIGH)
      end
      default: begin
        `uvm_error(`gfn, $sformatf("Unsupported Address space ID %d", asid))
      end
    endcase
  endfunction

  // Task: Start TLUL Sequences
  virtual task start_device(ref dma_seq_item dma_config);
    if (dma_config.handshake) begin
      // Assign memory models used in tl_device_vseq instances
      bit [31:0] fifo_interrupt_mask;
      bit fifo_intr_clear_en;
      bit [31:0] fifo_intr_clear_reg_addr;
      bit [31:0] fifo_intr_clear_val;
      // Variable to check if any of the handshake interrupt is asserted
      fifo_interrupt_mask = dma_config.handshake_intr_en & cfg.dma_vif.handshake_i;
      `uvm_info(`gfn, $sformatf("FIFO interrupt enable mask = %0x ", fifo_interrupt_mask),
                UVM_HIGH)
      fifo_intr_clear_en = fifo_interrupt_mask > 0;
      // Set fifo enable bit
      set_seq_fifo_read_mode(dma_config.src_asid, dma_config.get_read_fifo_en());
      set_seq_fifo_write_mode(dma_config.dst_asid, dma_config.get_write_fifo_en());
      // Get FIFO register clear enable
      if (fifo_intr_clear_en) begin
        // Get FIFO interrupt register address and value
        // Find the interrupt index with both handshake interrupt enable and clear_int_src
        for (int i = 0; i < dma_reg_pkg::NumIntClearSources; i++) begin
          // Check if at least one handshake interrupt is asserted and
          // clear_int_src is set
          if (dma_config.clear_int_src[i]) begin
            `uvm_info(`gfn, $sformatf("Detected FIFO reg clear enable at index : %0d", i),
                      UVM_HIGH)
            // Set FIFO interrupt clear address and values in corresponding pull sequence instance
            case (dma_config.clear_int_bus)
              0: seq_ctn.add_fifo_reg({dma_config.int_src_addr[i][31:2], 2'd0},
                                       dma_config.int_src_wr_val[i]);
              1: seq_host.add_fifo_reg({dma_config.int_src_addr[i][31:2], 2'd0},
                                        dma_config.int_src_wr_val[i]);
              default: begin end
            endcase
            break;
          end
        end
        // Set FIFO interrupt clear in corresponding pull sequence instance
        case (dma_config.clear_int_bus)
          0: seq_ctn.set_fifo_clear(fifo_intr_clear_en);
          1: seq_host.set_fifo_clear(fifo_intr_clear_en);
          default: begin end
        endcase
      end
    end

    `uvm_info(`gfn, "DMA: Starting Devices", UVM_HIGH)
    fork
      seq_ctn.start(p_sequencer.tl_sequencer_dma_ctn_h);
      seq_host.start(p_sequencer.tl_sequencer_dma_host_h);
      seq_sys.start(p_sequencer.tl_sequencer_dma_sys_h);
    join_none
  endtask: start_device

  // Method to terminate sequences gracefully
  virtual task stop_device();
    `uvm_info(`gfn, "DMA: Stopping Devices", UVM_HIGH)
    fork
      seq_ctn.seq_stop();
      seq_host.seq_stop();
      seq_sys.seq_stop();
    join
    // Clear FIFO mode enable bit
    set_seq_fifo_read_mode(OtInternalAddr, 0);
    set_seq_fifo_read_mode(SocControlAddr, 0);
    set_seq_fifo_read_mode(SocSystemAddr, 0);
    set_seq_fifo_write_mode(OtInternalAddr, 0);
    set_seq_fifo_write_mode(SocControlAddr, 0);
    set_seq_fifo_write_mode(SocSystemAddr, 0);
    // Clear FIFO write clear enable bit
    seq_ctn.set_fifo_clear(0);
    seq_host.set_fifo_clear(0);
    seq_sys.set_fifo_clear(0);
    // Clear bytes_sent
    seq_ctn.bytes_sent = 0;
    seq_host.bytes_sent = 0;
    seq_sys.bytes_sent = 0;
    // Disable FIFO
    cfg.fifo_host.disable_fifo();
    cfg.fifo_ctn.disable_fifo();
    cfg.fifo_sys.disable_fifo();
  endtask

  // Method to clear memory contents
  function void clear_memory();
    // Clear memory contents
    `uvm_info(`gfn, $sformatf("Clearing memory contents"), UVM_MEDIUM)
    cfg.mem_host.init();
    cfg.mem_ctn.init();
    cfg.mem_sys.init();
  endfunction

  // Task: Configures (optionally executes) DMA control registers
  task set_control_register(opcode_e op = OpcCopy, // OPCODE
                            bit first, // Initial transfer
                            bit hs, // Handshake Enable
                            bit buff, // Auto-increment Buffer Address
                            bit fifo, // Auto-increment FIFO Address
                            bit dir, // Direction
                            bit go); // Execute
    string tmpstr;
    tmpstr = go ? "Executing": "Setting";
    `uvm_info(`gfn, $sformatf(
                      "DMA: %s DMA Control Register OPCODE=%d FIRST=%d HS=%d BUF=%d FIFO=%d DIR=%d",
                      tmpstr, op, first, hs, buff, fifo, dir), UVM_HIGH)
    // Configure all fields except GO bit
    ral.control.opcode.set(int'(op));
    ral.control.initial_transfer.set(first);
    ral.control.hardware_handshake_enable.set(hs);
    ral.control.memory_buffer_auto_increment_enable.set(buff);
    ral.control.fifo_auto_increment_enable.set(fifo);
    ral.control.data_direction.set(dir);
    csr_update(.csr(ral.control));
    // Set GO bit
    ral.control.go.set(go);
    csr_update(.csr(ral.control));
  endtask: set_control_register

  // Task: Abort the current transaction
  task abort();
    ral.control.abort.set(1);
    csr_update(.csr(ral.control));
  endtask: abort

  // Task: Clear DMA Status
  task clear();
    `uvm_info(`gfn, "DMA: Clear DMA State", UVM_HIGH)
    csr_wr(ral.clear_state, 32'd1);
  endtask: clear

  // Task: Wait for Completion
  task wait_for_completion(output int status);
    int timeout = 1000;
    // Case 1.    Timeout due to simulation hang
    // Case 2.    Generic Mode - Completion
    // Case 3.    Generic Mode - Error
    // Case 4.    Handshake Mode - dma_plic_interrupt asserts
    fork
      begin
        // Case 1: Timeout condition
        delay(timeout);
        status = -1;
        `uvm_fatal(`gfn, $sformatf("ERROR: Timeout Condition Reached at %d cycles", timeout))
      end
      poll_status();
      begin
        wait(e_complete.triggered);
        status = 0;
        `uvm_info(`gfn, "DMA: Completion Seen", UVM_HIGH)
      end
      begin
        wait(e_aborted.triggered);
        status = 1;
        `uvm_info(`gfn, "DMA: Aborted Seen", UVM_HIGH)
      end
      begin
        wait(e_errored.triggered);
        if (sim_fatal_exit_on_dma_error) begin
          status = -1;
          `uvm_fatal(`gfn, "ERROR: dma_status.error asserted")
        end else begin
          status = 2;
          `uvm_info(`gfn, "DMA: Error Seen", UVM_HIGH)
        end
      end
      begin
        wait(e_sha2_digest_valid.triggered);
        status = 0;
        `uvm_info(`gfn, "DMA: SHA2 digest valid seen", UVM_HIGH)
      end
    join_any
    disable fork;
  endtask: wait_for_completion

  // Task: Continuously poll status until completion every N cycles
  task poll_status(int pollrate = 10);
    bit [31:0] v;

    `uvm_info(`gfn, "DMA: Polling DMA Status", UVM_HIGH)
    while (1) begin
      csr_rd(ral.status, v);
      if (v[0]) begin ->e_busy; end
      if (v[1]) begin ->e_complete; break; end
      if (v[2]) begin ->e_aborted;  break; end
      if (v[3]) begin ->e_errored;  break; end
      if (v[12]) begin ->e_sha2_digest_valid;  break; end
      delay(pollrate);
    end
  endtask: poll_status

  // Monitors busy bit in STATUS register
  task wait_for_idle();
    forever begin
      uvm_reg_data_t data;
      csr_rd(ral.status, data);
      if (!get_field_val(ral.status.busy, data)) begin
        `uvm_info(`gfn, "DMA in Idle state", UVM_MEDIUM)
        break;
      end
    end
  endtask

  // Task: Simulate a clock delay
  virtual task delay(int num = 1);
    cfg.clk_rst_vif.wait_clks(num);
  endtask: delay

  // Task to wait for transfer of specified number of bytes
   task wait_num_bytes_transfer(uint num_bytes);
     forever begin
       if (get_bytes_sent(dma_config) >= num_bytes) begin
         `uvm_info(`gfn, $sformatf("Got %d", num_bytes), UVM_DEBUG)
         break;
       end else begin
         delay(1);
       end
     end
   endtask

   // Task to read out the SHA digest
  task read_sha2_digest(input opcode_e op, output logic [511:0] digest);
    int sha_digest_size; // in 32-bit words
    string sha_mode;
    digest = '0;
    `uvm_info(`gfn, "DMA: Read SHA2 digest", UVM_MEDIUM)
    case (op)
      OpcSha256: begin
        sha_digest_size = 8;
        sha_mode = "SHA2-256";
      end
      OpcSha384: begin
        sha_digest_size = 12;
        sha_mode = "SHA2-384";
      end
      OpcSha512: begin
        sha_digest_size = 16;
        sha_mode = "SHA2-512";
      end
      default: begin
        `uvm_error(`gfn, $sformatf("Unsupported SHA2 opcode %d", op))
      end
    endcase

    for(int i = 0; i < sha_digest_size; ++i) begin
      csr_rd(ral.sha2_digest[i],  digest[i*32 +: 32]);
    end
    `uvm_info(`gfn, $sformatf("DMA: %s digest: %x", sha_mode, digest), UVM_MEDIUM)
  endtask

  // Return number of bytes transferred from interface corresponding to source ASID
  virtual function uint get_bytes_sent(ref dma_seq_item dma_config);
    case (dma_config.src_asid)
      OtInternalAddr: begin
        `uvm_info(`gfn, $sformatf("OTInternal bytes_sent = %0d", seq_host.bytes_sent), UVM_HIGH)
        return seq_host.bytes_sent;
      end
      SocControlAddr, OtExtFlashAddr: begin
        `uvm_info(`gfn, $sformatf("SocControlAddr bytes_sent = %0d", seq_ctn.bytes_sent), UVM_HIGH)
        return seq_ctn.bytes_sent;
      end
      SocSystemAddr: begin
        `uvm_info(`gfn, $sformatf("SocSystemAddr bytes_sent = %0d", seq_sys.bytes_sent), UVM_HIGH)
        return seq_sys.bytes_sent;
      end
      default: begin
        `uvm_error(`gfn, $sformatf("Unsupported Address space ID %d", dma_config.src_asid))
      end
    endcase
  endfunction

  // Body: Need to override for inherited tests
  task body();
    init_model();
    enable_interrupt();
  endtask: body
endclass
