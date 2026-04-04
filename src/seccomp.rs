/// Install a seccomp-bpf filter restricting syscalls to the event loop's needs.
/// Must be called after privilege drop and before the event loop.
///
/// Uses prctl(PR_SET_SECCOMP) with SECCOMP_MODE_FILTER.
/// If seccomp isn't available, fails silently.
pub fn install_filter() {
    #[cfg(target_arch = "x86_64")]
    {
        use std::mem;

        // x86_64 syscall numbers
        const SYS_READ: u32 = 0;
        const SYS_WRITE: u32 = 1;
        const SYS_CLOSE: u32 = 3;
        const SYS_POLL: u32 = 7;
        const SYS_IOCTL: u32 = 16;
        const SYS_NANOSLEEP: u32 = 35;
        const SYS_CLOCK_NANOSLEEP: u32 = 230;
        const SYS_KILL: u32 = 62;
        const SYS_WAIT4: u32 = 61;
        const SYS_CLOCK_GETTIME: u32 = 228;
        const SYS_RT_SIGRETURN: u32 = 15;
        const SYS_EXIT_GROUP: u32 = 231;
        const SYS_EXIT: u32 = 60;
        const SYS_SIGALTSTACK: u32 = 131;
        const SYS_MMAP: u32 = 9;
        const SYS_MUNMAP: u32 = 11;
        const SYS_MPROTECT: u32 = 10;
        const SYS_BRK: u32 = 12;
        const SYS_FUTEX: u32 = 202;
        const SYS_GETRANDOM: u32 = 318;
        const SYS_PPOLL: u32 = 271;
        const SYS_PSELECT6: u32 = 270;
        const SYS_FCNTL: u32 = 72;
        const SYS_GETPID: u32 = 39;

        // BPF instructions
        const BPF_LD: u16 = 0x00;
        const BPF_W: u16 = 0x00;
        const BPF_ABS: u16 = 0x20;
        const BPF_JMP: u16 = 0x05;
        const BPF_JEQ: u16 = 0x10;
        const BPF_K: u16 = 0x00;
        const BPF_RET: u16 = 0x06;

        const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
        const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;

        #[repr(C)]
        struct SockFilter {
            code: u16,
            jt: u8,
            jf: u8,
            k: u32,
        }

        #[repr(C)]
        struct SockFprog {
            len: u16,
            filter: *const SockFilter,
        }

        // offset of seccomp_data.nr (syscall number)
        const NR_OFFSET: u32 = 0;

        const SYS_FSTAT: u32 = 5;
        const SYS_LSEEK: u32 = 8;
        const SYS_ACCESS: u32 = 21;
        const SYS_DUP: u32 = 32;
        const SYS_DUP2: u32 = 33;
        const SYS_RT_SIGACTION: u32 = 13;
        const SYS_RT_SIGPROCMASK: u32 = 14;
        const SYS_OPENAT: u32 = 257;
        const SYS_NEWFSTATAT: u32 = 262;
        const SYS_SCHED_YIELD: u32 = 24;
        const SYS_GETDENTS64: u32 = 217;
        const SYS_PRLIMIT64: u32 = 302;
        const SYS_RSEQ: u32 = 334;
        const SYS_SET_ROBUST_LIST: u32 = 273;

        let allowed: &[u32] = &[
            SYS_READ,
            SYS_WRITE,
            SYS_CLOSE,
            SYS_FSTAT,
            SYS_LSEEK,
            SYS_POLL,
            SYS_PPOLL,
            SYS_PSELECT6,
            SYS_IOCTL,
            SYS_ACCESS,
            SYS_DUP,
            SYS_DUP2,
            SYS_NANOSLEEP,
            SYS_CLOCK_NANOSLEEP,
            SYS_KILL,
            SYS_WAIT4,
            SYS_CLOCK_GETTIME,
            SYS_RT_SIGRETURN,
            SYS_RT_SIGACTION,
            SYS_RT_SIGPROCMASK,
            SYS_SIGALTSTACK,
            SYS_EXIT_GROUP,
            SYS_EXIT,
            SYS_MMAP,
            SYS_MUNMAP,
            SYS_MPROTECT,
            SYS_BRK,
            SYS_FUTEX,
            SYS_GETRANDOM,
            SYS_FCNTL,
            SYS_GETPID,
            SYS_OPENAT,
            SYS_NEWFSTATAT,
            SYS_SCHED_YIELD,
            SYS_GETDENTS64,
            SYS_PRLIMIT64,
            SYS_RSEQ,
            SYS_SET_ROBUST_LIST,
        ];

        // Build BPF program: load syscall nr, check each allowed, kill otherwise
        let mut insns: Vec<SockFilter> = Vec::new();

        // Load syscall number
        insns.push(SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: NR_OFFSET,
        });

        let n = allowed.len();
        for (i, &nr) in allowed.iter().enumerate() {
            let remaining = n - i - 1;
            insns.push(SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: (remaining + 1) as u8, // jump to ALLOW
                jf: 0,                     // continue checking
                k: nr,
            });
        }

        // Default: kill
        insns.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        });

        // Allow
        insns.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        });

        let prog = SockFprog {
            len: insns.len() as u16,
            filter: insns.as_ptr(),
        };

        unsafe {
            // Allow setting seccomp filters without CAP_SYS_ADMIN
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            libc::prctl(
                libc::PR_SET_SECCOMP,
                2, // SECCOMP_MODE_FILTER
                &prog as *const SockFprog as libc::c_ulong,
                0,
                0,
            );
        }

        mem::forget(insns); // BPF filter must outlive the prctl
    }
}
