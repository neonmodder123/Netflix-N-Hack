// PS4 Lapse Configuration
// Ported from PS5 version for Netflix n Hack

FW_VERSION = "";
IS_PS4 = true;

PAGE_SIZE = 0x4000;
PHYS_PAGE_SIZE = 0x1000;

LIBKERNEL_HANDLE = 0x2001n;

// Socket constants - only define if not already in scope
// (inject.js defines some of these as const in the eval scope)
if (typeof AF_UNIX === 'undefined') AF_UNIX = 1n;
if (typeof AF_INET === 'undefined') AF_INET = 2n;
if (typeof AF_INET6 === 'undefined') AF_INET6 = 28n;

if (typeof SOCK_STREAM === 'undefined') SOCK_STREAM = 1n;
if (typeof SOCK_DGRAM === 'undefined') SOCK_DGRAM = 2n;

if (typeof IPPROTO_TCP === 'undefined') IPPROTO_TCP = 6n;
if (typeof IPPROTO_UDP === 'undefined') IPPROTO_UDP = 17n;
if (typeof IPPROTO_IPV6 === 'undefined') IPPROTO_IPV6 = 41n;

if (typeof SOL_SOCKET === 'undefined') SOL_SOCKET = 0xFFFFn;
if (typeof SO_REUSEADDR === 'undefined') SO_REUSEADDR = 4n;
if (typeof SO_LINGER === 'undefined') SO_LINGER = 0x80n;

// IPv6 socket options
if (typeof IPV6_PKTINFO === 'undefined') IPV6_PKTINFO = 46n;
if (typeof IPV6_NEXTHOP === 'undefined') IPV6_NEXTHOP = 48n;
if (typeof IPV6_RTHDR === 'undefined') IPV6_RTHDR = 51n;
if (typeof IPV6_TCLASS === 'undefined') IPV6_TCLASS = 61n;
if (typeof IPV6_2292PKTOPTIONS === 'undefined') IPV6_2292PKTOPTIONS = 25n;

// TCP socket options
if (typeof TCP_INFO === 'undefined') TCP_INFO = 32n;
if (typeof TCPS_ESTABLISHED === 'undefined') TCPS_ESTABLISHED = 4n;

// All syscalls from lapse.py (PS4)
// (SYSCALL object is already defined in inject.js, we just add properties)
SYSCALL.unlink = 0xAn;              // 10
SYSCALL.pipe = 42n;                 // 42
SYSCALL.getpid = 20n;               // 20
SYSCALL.getuid = 0x18n;             // 24
SYSCALL.connect = 98n;              // 98
SYSCALL.munmap = 0x49n;             // 73
SYSCALL.mprotect = 0x4An;           // 74
SYSCALL.getsockopt = 0x76n;         // 118
SYSCALL.socketpair = 0x87n;         // 135
SYSCALL.nanosleep = 0xF0n;          // 240
SYSCALL.sched_yield = 0x14Bn;       // 331
SYSCALL.thr_exit = 0x1AFn;          // 431
SYSCALL.thr_self = 0x1B0n;          // 432
SYSCALL.thr_new = 0x1C7n;           // 455
SYSCALL.rtprio_thread = 0x1D2n;     // 466
SYSCALL.mmap = 477n;                // 477
SYSCALL.cpuset_getaffinity = 0x1E7n; // 487
SYSCALL.cpuset_setaffinity = 0x1E8n; // 488
SYSCALL.jitshm_create = 0x215n;     // 533
SYSCALL.evf_create = 0x21An;        // 538
SYSCALL.evf_delete = 0x21Bn;        // 539
SYSCALL.evf_set = 0x220n;           // 544
SYSCALL.evf_clear = 0x221n;         // 545
SYSCALL.is_in_sandbox = 0x249n;     // 585
SYSCALL.dlsym = 0x24Fn;             // 591
SYSCALL.thr_suspend_ucontext = 0x278n; // 632
SYSCALL.thr_resume_ucontext = 0x279n; // 633
SYSCALL.aio_multi_delete = 0x296n;  // 662
SYSCALL.aio_multi_wait = 0x297n;    // 663
SYSCALL.aio_multi_poll = 0x298n;    // 664
SYSCALL.aio_multi_cancel = 0x29An;  // 666
SYSCALL.aio_submit_cmd = 0x29Dn;    // 669
SYSCALL.kexec = 0x295n;             // 661

MAIN_CORE = 4;  // Same as yarpe
MAIN_RTPRIO = 0x100;
NUM_WORKERS = 2;
NUM_GROOMS = 0x200;
NUM_HANDLES = 0x100;
NUM_SDS = 64;
NUM_SDS_ALT = 48;
NUM_RACES = 100;
NUM_ALIAS = 100;
LEAK_LEN = 16;
NUM_LEAKS = 32;
NUM_CLOBBERS = 8;
MAX_AIO_IDS = 0x80;

AIO_CMD_READ = 1n;
AIO_CMD_FLAG_MULTI = 0x1000n;
AIO_CMD_MULTI_READ = 0x1001n;
AIO_CMD_WRITE = 2n;
AIO_STATE_COMPLETE = 3n;
AIO_STATE_ABORTED = 4n;

SCE_KERNEL_ERROR_ESRCH = 0x80020003n;

RTP_SET = 1n;
PRI_REALTIME = 2n;

// TCP info structure size for getsockopt
size_tcp_info = 0xEC;

block_fd = 0xffffffffffffffffn;
unblock_fd = 0xffffffffffffffffn;
block_id = -1n;
groom_ids = null;
sds = null;
sds_alt = null;
prev_core = -1;
prev_rtprio = 0n;
ready_signal = 0n;
deletion_signal = 0n;
pipe_buf = 0n;

saved_fpu_ctrl = 0;
saved_mxcsr = 0;

function sysctlbyname(name, oldp, oldp_len, newp, newp_len) {
    const translate_name_mib = malloc(0x8);
    const buf_size = 0x70;
    const mib = malloc(buf_size);
    const size = malloc(0x8);

    write64_uncompressed(translate_name_mib, 0x300000000n);
    write64_uncompressed(size, BigInt(buf_size));

    const name_addr = alloc_string(name);
    const name_len = BigInt(name.length);

    if (syscall(SYSCALL.sysctl, translate_name_mib, 2n, mib, size, name_addr, name_len) === 0xffffffffffffffffn) {
        throw new Error("failed to translate sysctl name to mib (" + name + ")");
    }

    if (syscall(SYSCALL.sysctl, mib, 2n, oldp, oldp_len, newp, newp_len) === 0xffffffffffffffffn) {
        return false;
    }

    return true;
}
