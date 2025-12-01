/*
    PS4 BinLoader - ELF/Binary Loader

    After jailbreak, starts a TCP server on port 9021.
    Send an ELF binary to load and execute it.

    Requires: lapse_stages.js (Stage 2-4 functions)
*/

// === BinLoader Constants ===
const BIN_LOADER_PORT = 9021;
const MAX_PAYLOAD_SIZE = 4 * 1024 * 1024;  // 4MB
const READ_CHUNK = 4096;
const ELF_MAGIC = 0x464C457Fn;  // "\x7fELF" as little-endian

const BL_MAP_PRIVATE = 0x2n;
const BL_MAP_ANONYMOUS = 0x1000n;
const BL_PROT_READ = 0x1n;
const BL_PROT_WRITE = 0x2n;
const BL_PROT_EXEC = 0x4n;

// Syscalls not in inject.js SYSCALL object
const BL_SYSCALL_MMAP = 477;    // 0x1DD
const BL_SYSCALL_GETPID = 20;   // 0x14

// === BinLoader Functions ===

function bl_create_listen_socket(port) {
    const sd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
    if (sd === 0xffffffffffffffffn) {
        throw new Error("socket() failed");
    }

    const enable = malloc(4);
    write32_uncompressed(enable, 1);
    syscall(SYSCALL.setsockopt, sd, SOL_SOCKET, SO_REUSEADDR, enable, 4n);

    const sockaddr = malloc(16);
    for (let j = 0; j < 16; j++) {
        write8_uncompressed(sockaddr + BigInt(j), 0);
    }
    write8_uncompressed(sockaddr + 1n, AF_INET);
    write8_uncompressed(sockaddr + 2n, (port >> 8) & 0xff);
    write8_uncompressed(sockaddr + 3n, port & 0xff);
    write32_uncompressed(sockaddr + 4n, 0);  // INADDR_ANY

    let ret = syscall(SYSCALL.bind, sd, sockaddr, 16n);
    if (ret === 0xffffffffffffffffn) {
        syscall(SYSCALL.close, sd);
        throw new Error("bind() failed");
    }

    ret = syscall(SYSCALL.listen, sd, 1n);
    if (ret === 0xffffffffffffffffn) {
        syscall(SYSCALL.close, sd);
        throw new Error("listen() failed");
    }

    return sd;
}

function bl_read_payload_from_socket(client_sock, max_size) {
    const buf = malloc(READ_CHUNK);
    const payload_buf = malloc(max_size);
    let total_read = 0;

    while (total_read < max_size) {
        const read_size = syscall(SYSCALL.read, client_sock, buf, BigInt(READ_CHUNK));

        if (read_size === 0xffffffffffffffffn) {
            throw new Error("read() failed");
        }

        if (read_size === 0n) {
            break;  // EOF
        }

        const bytes_read = Number(read_size);

        for (let j = 0; j < bytes_read; j++) {
            write8_uncompressed(payload_buf + BigInt(total_read + j),
                               read8_uncompressed(buf + BigInt(j)));
        }

        total_read += bytes_read;

        if (total_read % (64 * 1024) === 0) {
            logger.log("Received " + total_read + " bytes...");
            logger.flush();
        }
    }

    return { buf: payload_buf, size: total_read };
}

function bl_load_elf(buf_addr, buf_size) {
    // Check ELF magic
    const magic = read32_uncompressed(buf_addr);
    logger.log("First 4 bytes (magic): " + hex(magic));
    // Compare as numbers since ELF_MAGIC is a Number constant
    if (Number(magic) !== ELF_MAGIC) {
        logger.log("Not an ELF file, treating as raw shellcode");
        return { is_elf: false };
    }

    // Read ELF header
    const e_entry = read64_uncompressed(buf_addr + 0x18n);
    const e_phoff = read64_uncompressed(buf_addr + 0x20n);
    const e_phentsize = Number(read16_uncompressed(buf_addr + 0x36n));
    const e_phnum = Number(read16_uncompressed(buf_addr + 0x38n));

    logger.log("ELF entry: " + hex(e_entry));
    logger.log("Program headers: " + e_phnum + " @ offset " + hex(e_phoff));

    // Calculate total memory needed
    let max_addr = 0n;
    for (let i = 0; i < e_phnum; i++) {
        const phdr_addr = buf_addr + e_phoff + BigInt(i * e_phentsize);
        const p_type = Number(read32_uncompressed(phdr_addr));
        if (p_type === 1) {  // PT_LOAD
            const p_vaddr = read64_uncompressed(phdr_addr + 0x10n);
            const p_memsz = read64_uncompressed(phdr_addr + 0x28n);
            const end = (p_vaddr & 0xffffffn) + p_memsz;
            if (end > max_addr) max_addr = end;
        }
    }

    return {
        is_elf: true,
        e_entry: e_entry,
        e_phoff: e_phoff,
        e_phentsize: e_phentsize,
        e_phnum: e_phnum,
        total_size: Number(max_addr)
    };
}

function bl_mmap_rwx(size) {
    // After kernel patches, regular mmap with PROT_RWX should work
    // The kpatches modify sys_mmap() to allow RWX mappings
    const prot = BL_PROT_READ | BL_PROT_WRITE | BL_PROT_EXEC;
    const flags = BL_MAP_PRIVATE | BL_MAP_ANONYMOUS;

    const ret = syscall(BL_SYSCALL_MMAP, 0n, BigInt(size), prot, flags, 0xffffffffffffffffn, 0n);

    logger.log("mmap(" + size + ") returned: " + hex(ret));

    if (ret >= 0xffff800000000000n) {
        throw new Error("mmap failed: " + hex(ret));
    }

    return ret;
}

function bl_load_segments(buf_addr, elf_info, mmap_base) {
    for (let i = 0; i < elf_info.e_phnum; i++) {
        const phdr_addr = buf_addr + elf_info.e_phoff + BigInt(i * elf_info.e_phentsize);
        const p_type = Number(read32_uncompressed(phdr_addr));

        if (p_type === 1) {  // PT_LOAD
            const p_offset = read64_uncompressed(phdr_addr + 0x08n);
            const p_vaddr = read64_uncompressed(phdr_addr + 0x10n);
            const p_filesz = Number(read64_uncompressed(phdr_addr + 0x20n));
            const p_memsz = Number(read64_uncompressed(phdr_addr + 0x28n));

            const seg_offset = p_vaddr & 0xffffffn;
            const seg_addr = mmap_base + seg_offset;

            logger.log("Loading segment " + i + ": " + hex(p_vaddr) + " -> " + hex(seg_addr) + " (" + p_filesz + " bytes)");

            // Copy segment data
            for (let j = 0; j < p_filesz; j++) {
                const byte = read8_uncompressed(buf_addr + p_offset + BigInt(j));
                write8_uncompressed(seg_addr + BigInt(j), byte);
            }

            // Zero BSS (memsz - filesz)
            for (let j = p_filesz; j < p_memsz; j++) {
                write8_uncompressed(seg_addr + BigInt(j), 0);
            }
        }
    }

    // Return entry point
    const entry_offset = elf_info.e_entry & 0xffffffn;
    return mmap_base + entry_offset;
}

function bin_loader_main() {
    logger.log("");
    logger.log("=== PS4 Binary Loader ===");
    logger.log("Starting payload server on port " + BIN_LOADER_PORT);
    logger.flush();

    let server_sock;
    try {
        server_sock = bl_create_listen_socket(BIN_LOADER_PORT);
    } catch (e) {
        logger.log("ERROR: " + e.message);
        send_notification("Bin loader failed!\n" + e.message);
        return false;
    }

    const ip = get_current_ip();
    const addr_str = (ip ? ip : "<PS4 IP>") + ":" + BIN_LOADER_PORT;

    logger.log("Listening on " + addr_str);
    logger.log("Send your ELF payload now...");
    logger.flush();
    send_notification("Jailbreak OK!\nSend ELF to:\n" + addr_str);

    // Accept client
    const sockaddr = malloc(16);
    const sockaddr_len = malloc(4);
    write32_uncompressed(sockaddr_len, 16);

    const client_sock = syscall(SYSCALL.accept, server_sock, sockaddr, sockaddr_len);
    if (client_sock === 0xffffffffffffffffn) {
        logger.log("ERROR: accept() failed");
        syscall(SYSCALL.close, server_sock);
        return false;
    }

    logger.log("Client connected!");
    logger.flush();

    let payload;
    try {
        payload = bl_read_payload_from_socket(client_sock, MAX_PAYLOAD_SIZE);
    } catch (e) {
        logger.log("ERROR reading payload: " + e.message);
        syscall(SYSCALL.close, client_sock);
        syscall(SYSCALL.close, server_sock);
        return false;
    }

    logger.log("Received " + payload.size + " bytes");
    syscall(SYSCALL.close, client_sock);
    syscall(SYSCALL.close, server_sock);

    if (payload.size < 64) {
        logger.log("ERROR: Payload too small");
        return false;
    }

    // Parse and load ELF
    const elf_info = bl_load_elf(payload.buf, payload.size);

    let mmap_size, mmap_base, entry_point;

    if (elf_info.is_elf) {
        mmap_size = Math.max(elf_info.total_size, payload.size);
        mmap_size = ((mmap_size + 0xfff) & ~0xfff);  // Round to page

        logger.log("Allocating " + mmap_size + " bytes RWX...");
        mmap_base = bl_mmap_rwx(mmap_size);
        logger.log("mmap() at: " + hex(mmap_base));

        entry_point = bl_load_segments(payload.buf, elf_info, mmap_base);
    } else {
        // Raw shellcode - allocate RWX memory directly (kpatches enable this)
        mmap_size = ((payload.size + 0xfff) & ~0xfff);
        logger.log("Allocating " + mmap_size + " bytes RWX...");
        mmap_base = bl_mmap_rwx(mmap_size);
        logger.log("RWX memory at: " + hex(mmap_base));

        // Copy raw shellcode
        logger.log("Copying " + payload.size + " bytes...");
        for (let i = 0; i < payload.size; i++) {
            const byte = read8_uncompressed(payload.buf + BigInt(i));
            write8_uncompressed(mmap_base + BigInt(i), byte);
        }

        // Entry point is start of shellcode
        entry_point = mmap_base;
    }

    logger.log("Entry point: " + hex(entry_point));
    logger.log("");
    logger.log("Payload loaded! Spawning thread...");
    logger.flush();

    // Use call() for Thrd_create (simpler, worked before)
    try {
        const THRD_CREATE_OFFSET = 0x4c770n;
        const Thrd_create = libc_base + THRD_CREATE_OFFSET;

        logger.log("libc_base: " + hex(libc_base));
        logger.log("Thrd_create: " + hex(Thrd_create));
        logger.flush();

        const thr_handle_addr = malloc(8);

        // Raw shellcode - no args (like bin_loader.py)
        logger.log("Calling Thrd_create(handle, entry)...");
        logger.flush();

        const ret = call(Thrd_create, thr_handle_addr, entry_point);
        logger.log("Thrd_create returned: " + hex(ret));

        if (ret !== 0n) {
            logger.log("ERROR: Thrd_create failed");
            return false;
        }

        const thr_handle = read64_uncompressed(thr_handle_addr);
        logger.log("Thread handle: " + hex(thr_handle));
        logger.flush();

        send_notification("Payload spawned!");
        logger.log("Thread spawned! Waiting with Thrd_join...");
        logger.flush();

        // Wait for payload using Thrd_join (like yarpe bin_loader.py)
        const THRD_JOIN_OFFSET = 0x4c570n;
        const Thrd_join = libc_base + THRD_JOIN_OFFSET;
        logger.log("Thrd_join: " + hex(Thrd_join));

        const join_ret = call(Thrd_join, thr_handle, 0n);
        logger.log("Thrd_join returned: " + hex(join_ret));
        logger.flush();

        // Now kill
        logger.log("Payload done, killing game...");
        const pid = syscall(SYSCALL.getpid);
        syscall(SYSCALL.kill, pid, 9n);

        return true;

    } catch (e) {
        logger.log("ERROR spawning thread: " + e.message);
        logger.log(e.stack);
        return false;
    }
}

// === Execute ===
bin_loader_main();
