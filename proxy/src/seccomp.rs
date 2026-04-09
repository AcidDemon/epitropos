pub fn install_filter() {
    let syscalls = allowed_syscalls();
    if syscalls.is_empty() {
        return;
    }
    install_bpf(&syscalls);
}

#[cfg(target_arch = "x86_64")]
fn allowed_syscalls() -> Vec<u32> {
    vec![
        0,   // read
        1,   // write
        3,   // close
        5,   // fstat
        7,   // poll
        8,   // lseek
        9,   // mmap
        10,  // mprotect (arg checked below isn't possible in basic BPF, so allowed)
        11,  // munmap
        12,  // brk
        13,  // rt_sigaction
        14,  // rt_sigprocmask
        15,  // rt_sigreturn
        16,  // ioctl
        17,  // pread64
        18,  // pwrite64
        19,  // readv
        20,  // writev
        21,  // access
        24,  // sched_yield
        32,  // dup
        33,  // dup2
        35,  // nanosleep
        39,  // getpid
        41,  // socket
        42,  // connect
        44,  // sendto
        60,  // exit
        61,  // wait4
        72,  // fcntl
        73,  // flock (utmp cleanup)
        131, // sigaltstack
        186, // gettid
        202, // futex
        217, // getdents64
        228, // clock_gettime
        230, // clock_nanosleep
        231, // exit_group
        234, // tgkill
        257, // openat
        262, // newfstatat
        270, // pselect6
        271, // ppoll
        273, // set_robust_list
        302, // prlimit64
        318, // getrandom
        334, // rseq
    ]
}

#[cfg(target_arch = "aarch64")]
fn allowed_syscalls() -> Vec<u32> {
    vec![
        63,  // read
        64,  // write
        57,  // close
        80,  // fstat
        73,  // ppoll
        62,  // lseek
        222, // mmap
        226, // mprotect
        215, // munmap
        214, // brk
        134, // rt_sigaction
        135, // rt_sigprocmask
        139, // rt_sigreturn
        29,  // ioctl
        67,  // pread64
        68,  // pwrite64
        65,  // readv
        66,  // writev
        21,  // access (via faccessat on aarch64: 48)
        48,  // faccessat
        124, // sched_yield
        23,  // dup
        24,  // dup3
        101, // nanosleep
        172, // getpid
        198, // socket
        203, // connect
        206, // sendto
        93,  // exit
        95,  // wait4 (waitid: 95)
        260, // wait4
        25,  // fcntl
        32,  // flock (utmp cleanup)
        132, // sigaltstack
        178, // gettid
        98,  // futex
        61,  // getdents64
        113, // clock_gettime
        115, // clock_nanosleep
        94,  // exit_group
        131, // tgkill
        56,  // openat
        79,  // newfstatat
        72,  // pselect6
        273, // set_robust_list
        261, // prlimit64
        278, // getrandom
        293, // rseq
    ]
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn allowed_syscalls() -> Vec<u32> {
    compile_error!(
        "seccomp syscall table not defined for this architecture — add it or disable seccomp"
    );
}

#[allow(clippy::vec_init_then_push)]
fn install_bpf(allowed: &[u32]) {
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;

    #[cfg(target_arch = "x86_64")]
    const EXPECTED_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
    #[cfg(target_arch = "aarch64")]
    const EXPECTED_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

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

    let n = allowed.len();
    assert!(
        n <= 254,
        "seccomp: too many allowed syscalls for BPF u8 jump offsets"
    );

    let mut insns: Vec<SockFilter> = Vec::new();

    // Load arch field (offset 4 in seccomp_data)
    insns.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 4,
    });
    // Kill if architecture doesn't match (prevents 32-bit syscall bypass)
    insns.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 1, // skip kill, continue to syscall check
        jf: 0, // fall through to kill
        k: EXPECTED_ARCH,
    });
    insns.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    // Load syscall number (offset 0 in seccomp_data)
    insns.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });

    for (i, &nr) in allowed.iter().enumerate() {
        let remaining = n - i - 1;
        insns.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: (remaining + 1) as u8,
            jf: 0,
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
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            eprintln!(
                "epitropos: fatal: PR_SET_NO_NEW_PRIVS failed: {}",
                std::io::Error::last_os_error()
            );
            libc::_exit(1);
        }
        if libc::prctl(
            libc::PR_SET_SECCOMP,
            2,
            &prog as *const SockFprog as libc::c_ulong,
            0,
            0,
        ) != 0
        {
            eprintln!(
                "epitropos: fatal: PR_SET_SECCOMP failed: {}",
                std::io::Error::last_os_error()
            );
            libc::_exit(1);
        }
    }
    // insns drops here — kernel already copied the BPF program during prctl
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_list_within_bpf_jump_limit() {
        let syscalls = allowed_syscalls();
        assert!(
            syscalls.len() <= 254,
            "allowed syscalls ({}) exceeds BPF u8 jump limit",
            syscalls.len()
        );
    }

    #[test]
    fn no_duplicate_syscalls() {
        let syscalls = allowed_syscalls();
        let mut sorted = syscalls.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(syscalls.len(), sorted.len(), "duplicate syscall numbers");
    }

    #[test]
    fn dangerous_syscalls_not_in_list() {
        let syscalls = allowed_syscalls();
        #[cfg(target_arch = "x86_64")]
        {
            assert!(!syscalls.contains(&56), "clone should not be allowed");
            assert!(!syscalls.contains(&59), "execve should not be allowed");
            assert!(!syscalls.contains(&435), "clone3 should not be allowed");
            assert!(!syscalls.contains(&62), "kill should not be allowed");
        }
        #[cfg(target_arch = "aarch64")]
        {
            assert!(!syscalls.contains(&220), "clone should not be allowed");
            assert!(!syscalls.contains(&221), "execve should not be allowed");
            assert!(!syscalls.contains(&435), "clone3 should not be allowed");
            assert!(!syscalls.contains(&129), "kill should not be allowed");
        }
    }
}
