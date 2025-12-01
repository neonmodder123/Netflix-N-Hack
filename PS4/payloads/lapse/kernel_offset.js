// PS4 Kernel Offsets for Lapse exploit
// Source: https://github.com/Helloyunho/yarpe/blob/main/payloads/lapse.py

// Firmware-specific offsets for PS4

offset_ps4_9_00 = {
    EVF_OFFSET: 0x7F6F27n,
    PRISON0: 0x111F870n,
    ROOTVNODE: 0x21EFF20n,
    TARGET_ID_OFFSET: 0x221688Dn,
    SYSENT_661: 0x1107F00n,
    JMP_RSI_GADGET: 0x4C7ADn,
};

offset_ps4_9_03 = {
    EVF_OFFSET: 0x7F4CE7n,
    PRISON0: 0x111B840n,
    ROOTVNODE: 0x21EBF20n,
    TARGET_ID_OFFSET: 0x221288Dn,
    SYSENT_661: 0x1103F00n,
    JMP_RSI_GADGET: 0x5325Bn,
};

offset_ps4_9_50 = {
    EVF_OFFSET: 0x769A88n,
    PRISON0: 0x11137D0n,
    ROOTVNODE: 0x21A6C30n,
    TARGET_ID_OFFSET: 0x221A40Dn,
    SYSENT_661: 0x1100EE0n,
    JMP_RSI_GADGET: 0x15A6Dn,
};

offset_ps4_10_00 = {
    EVF_OFFSET: 0x7B5133n,
    PRISON0: 0x111B8B0n,
    ROOTVNODE: 0x1B25BD0n,
    TARGET_ID_OFFSET: 0x1B9E08Dn,
    SYSENT_661: 0x110A980n,
    JMP_RSI_GADGET: 0x68B1n,
};

offset_ps4_10_50 = {
    EVF_OFFSET: 0x7A7B14n,
    PRISON0: 0x111B910n,
    ROOTVNODE: 0x1BF81F0n,
    TARGET_ID_OFFSET: 0x1BE460Dn,
    SYSENT_661: 0x110A5B0n,
    JMP_RSI_GADGET: 0x50DEDn,
};

offset_ps4_11_00 = {
    EVF_OFFSET: 0x7FC26Fn,
    PRISON0: 0x111F830n,
    ROOTVNODE: 0x2116640n,
    TARGET_ID_OFFSET: 0x221C60Dn,
    SYSENT_661: 0x1109350n,
    JMP_RSI_GADGET: 0x71A21n,
};

offset_ps4_11_02 = {
    EVF_OFFSET: 0x7FC22Fn,
    PRISON0: 0x111F830n,
    ROOTVNODE: 0x2116640n,
    TARGET_ID_OFFSET: 0x221C60Dn,
    SYSENT_661: 0x1109350n,
    JMP_RSI_GADGET: 0x71A21n,
};

offset_ps4_11_50 = {
    EVF_OFFSET: 0x784318n,
    PRISON0: 0x111FA18n,
    ROOTVNODE: 0x2136E90n,
    TARGET_ID_OFFSET: 0x21CC60Dn,
    SYSENT_661: 0x110A760n,
    JMP_RSI_GADGET: 0x704D5n,
};

offset_ps4_12_00 = {
    EVF_OFFSET: 0x784798n,
    PRISON0: 0x111FA18n,
    ROOTVNODE: 0x2136E90n,
    TARGET_ID_OFFSET: 0x21CC60Dn,
    SYSENT_661: 0x110A760n,
    JMP_RSI_GADGET: 0x47B31n,
};

// Map firmware versions to offset objects
ps4_kernel_offset_list = {
    "9.00": offset_ps4_9_00,
    "9.03": offset_ps4_9_03,
    "9.04": offset_ps4_9_03,
    "9.50": offset_ps4_9_50,
    "9.51": offset_ps4_9_50,
    "9.60": offset_ps4_9_50,
    "10.00": offset_ps4_10_00,
    "10.01": offset_ps4_10_00,
    "10.50": offset_ps4_10_50,
    "10.70": offset_ps4_10_50,
    "10.71": offset_ps4_10_50,
    "11.00": offset_ps4_11_00,
    "11.02": offset_ps4_11_02,
    "11.50": offset_ps4_11_50,
    "11.52": offset_ps4_11_50,
    "12.00": offset_ps4_12_00,
    "12.02": offset_ps4_12_00,
};

kernel_offset = null;

function get_kernel_offset(FW_VERSION) {
    const fw_offsets = ps4_kernel_offset_list[FW_VERSION];

    if (!fw_offsets) {
        throw new Error("Unsupported PS4 firmware version: " + FW_VERSION);
    }

    kernel_offset = { ...fw_offsets };

    // PS4-specific proc structure offsets
    kernel_offset.PROC_FD = 0x48n;
    kernel_offset.PROC_PID = 0xB0n;       // PS4 = 0xB0, PS5 = 0xBC
    kernel_offset.PROC_VM_SPACE = 0x200n;
    kernel_offset.PROC_UCRED = 0x40n;
    kernel_offset.PROC_COMM = -1n;        // Found dynamically
    kernel_offset.PROC_SYSENT = -1n;      // Found dynamically

    // filedesc - PS4 different from PS5
    kernel_offset.FILEDESC_OFILES = 0x0n;  // PS4 = 0x0, PS5 = 0x8
    kernel_offset.SIZEOF_OFILES = 0x8n;    // PS4 = 0x8, PS5 = 0x30

    // vmspace structure
    kernel_offset.VMSPACE_VM_PMAP = -1n;

    // pmap structure
    kernel_offset.PMAP_CR3 = 0x28n;

    // socket/net - PS4 specific
    kernel_offset.SO_PCB = 0x18n;
    kernel_offset.INPCB_PKTOPTS = 0x118n;  // PS4 = 0x118, PS5 = 0x120

    // pktopts structure - PS4 specific
    kernel_offset.IP6PO_TCLASS = 0xB0n;    // PS4 = 0xB0, PS5 = 0xC0
    kernel_offset.IP6PO_RTHDR = 0x68n;     // PS4 = 0x68, PS5 = 0x70

    return kernel_offset;
}

function find_proc_offsets() {
    const proc_data = kernel.read_buffer(kernel.addr.curproc, 0x1000);

    // Look for patterns to find dynamic offsets
    const p_comm_sign = find_pattern(proc_data, "ce fa ef be cc bb");
    const p_sysent_sign = find_pattern(proc_data, "ff ff ff ff ff ff ff 7f");

    if (p_comm_sign.length === 0) {
        throw new Error("failed to find offset for PROC_COMM");
    }

    if (p_sysent_sign.length === 0) {
        throw new Error("failed to find offset for PROC_SYSENT");
    }

    const p_comm_offset = BigInt(p_comm_sign[0] + 0x8);
    const p_sysent_offset = BigInt(p_sysent_sign[0] - 0x10);

    return {
        PROC_COMM: p_comm_offset,
        PROC_SYSENT: p_sysent_offset
    };
}

function update_kernel_offsets() {
    const offsets = find_proc_offsets();

    for (const [key, value] of Object.entries(offsets)) {
        kernel_offset[key] = value;
    }
}
