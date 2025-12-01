function find_pattern(buffer, pattern_string) {
    const parts = pattern_string.split(' ');
    const matches = [];

    for (let i = 0; i <= buffer.length - parts.length; i++) {
        let match = true;

        for (let j = 0; j < parts.length; j++) {
            if (parts[j] === '?') continue;
            if (buffer[i + j] !== parseInt(parts[j], 16)) {
                match = false;
                break;
            }
        }

        if (match) matches.push(i);
    }

    return matches;
}

function get_fwversion() {
    const buf = malloc(0x8);
    const size = malloc(0x8);
    write64_uncompressed(size, 0x8n);

    if (sysctlbyname("kern.sdk_version", buf, size, 0n, 0n)) {
        const byte1 = Number(read8_uncompressed(buf + 2n));  // Minor version (first byte)
        const byte2 = Number(read8_uncompressed(buf + 3n));  // Major version (second byte)

        const version = byte2.toString(16) + '.' + byte1.toString(16).padStart(2, '0');
        return version;
    }

    return null;
}

function create_pipe() {
    const fildes = malloc(0x10);

    logger.log("      create_pipe: calling pipe syscall...");
    logger.flush();

    // Use the standard syscall() function from inject.js
    const result = syscall(SYSCALL.pipe, fildes);

    logger.log("      create_pipe: pipe returned " + hex(result));
    logger.flush();

    if (result === 0xffffffffffffffffn) {
        throw new Error("pipe syscall failed");
    }

    const read_fd = read32_uncompressed(fildes);
    const write_fd = read32_uncompressed(fildes + 4n);
    logger.log("      create_pipe: read_fd=" + hex(read_fd) + " write_fd=" + hex(write_fd));
    logger.flush();
    return [read_fd, write_fd];
}

function read_buffer(addr, len) {
    const buffer = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        buffer[i] = Number(read8_uncompressed(addr + BigInt(i)));
    }
    return buffer;
}

function read_cstring(addr) {
    let str = "";
    let i = 0n;
    while (true) {
        const c = Number(read8_uncompressed(addr + i));
        if (c === 0) break;
        str += String.fromCharCode(c);
        i++;
        if (i > 256n) break; // Safety limit
    }
    return str;
}

function write_buffer(addr, buffer) {
    for (let i = 0; i < buffer.length; i++) {
        write8_uncompressed(addr + BigInt(i), buffer[i]);
    }
}

function get_nidpath() {
    const path_buffer = malloc(0x255);
    const len_ptr = malloc(8);

    write64_uncompressed(len_ptr, 0x255n);

    const ret = syscall(SYSCALL.randomized_path, 0n, path_buffer, len_ptr);
    if (ret === 0xffffffffffffffffn) {
        throw new Error("randomized_path failed : " + hex(ret));
    }

    return read_cstring(path_buffer);
}

function nanosleep(nsec) {
    const timespec = malloc(0x10);
    write64_uncompressed(timespec, BigInt(Math.floor(nsec / 1e9)));    // tv_sec
    write64_uncompressed(timespec + 8n, BigInt(nsec % 1e9));           // tv_nsec
    syscall(SYSCALL.nanosleep, timespec);
}

function is_jailbroken() {
    const cur_uid = syscall(SYSCALL.getuid);
    const is_in_sandbox = syscall(SYSCALL.is_in_sandbox);
    if (cur_uid === 0n && is_in_sandbox === 0n) {
        return true;
    } else {

        // Check if elfldr is running at 9021
        const sockaddr_in = malloc(16);
        const enable = malloc(4);

        const sock_fd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
        if (sock_fd === 0xffffffffffffffffn) {
            throw new Error("socket failed: " + hex(sock_fd));
        }

        try {
            write32_uncompressed(enable, 1);
            syscall(SYSCALL.setsockopt, sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4n);

            write8_uncompressed(sockaddr_in + 1n, AF_INET);
            write16_uncompressed(sockaddr_in + 2n, 0x3D23n);      // port 9021
            write32_uncompressed(sockaddr_in + 4n, 0x0100007Fn);  // 127.0.0.1

            // Try to connect to 127.0.0.1:9021
            const ret = syscall(SYSCALL.connect, sock_fd, sockaddr_in, 16n);

            if (ret === 0n) {
                syscall(SYSCALL.close, sock_fd);
                return true;
            } else {
                syscall(SYSCALL.close, sock_fd);
                return false;
            }
        } catch (e) {
            syscall(SYSCALL.close, sock_fd);
            return false;
        }
    }
}

function check_jailbroken() {
    if (!is_jailbroken()) {
        throw new Error("process is not jailbroken")
    }
}

function file_exists(path) {
    const path_addr = alloc_string(path);
    const fd = syscall(SYSCALL.open, path_addr, O_RDONLY);

    if (fd !== 0xffffffffffffffffn) {
        syscall(SYSCALL.close, fd);
        return true;
    } else {
        return false;
    }
}

function write_file(path, text) {
    const mode = 0x1ffn; // 777
    const path_addr = alloc_string(path);
    const data_addr = alloc_string(text);

    const flags = O_CREAT | O_WRONLY | O_TRUNC;
    const fd = syscall(SYSCALL.open, path_addr, flags, mode);

    if (fd === 0xffffffffffffffffn) {
        throw new Error("open failed for " + path + " fd: " + hex(fd));
    }

    const written = syscall(SYSCALL.write, fd, data_addr, BigInt(text.length));
    if (written === 0xffffffffffffffffn) {
        syscall(SYSCALL.close, fd);
        throw new Error("write failed : " + hex(written));
    }

    syscall(SYSCALL.close, fd);
    return Number(written); // number of bytes written
}
