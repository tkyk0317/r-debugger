use nix::sys::wait::*;
use nix::unistd::{ Pid };
use nix::sys::ptrace::{ setoptions, syscall, getregs, Options };

// システムコールトレーサー
pub struct Tracer {
    pid: Pid
}

/// strace実装
impl Tracer {
    /// コンストラクタ
    pub fn new(pid: Pid) -> Self {
        Tracer {
            pid: pid
        }
    }

    /// システムコールトレース
    pub fn start(&self) {
        println!("start stracer({})", self.pid);

        // 子プロセスWait
        loop {
            match nix::sys::wait::waitpid(self.pid, None).expect("wait child process failed") {
                // 子プロセスからのシグナル待ち
                WaitStatus::Exited(pid, status) => {
                    println!("[trace_syscall] exit child process: pid={:?}, status={:?}", pid, status);
                    break;
                }
                WaitStatus::PtraceSyscall(pid) => {
                    // syscall分析
                    self.analysis_syscall();

                    // プロセス再開
                    syscall(pid, None).expect("failed syscall");
                }
                WaitStatus::Stopped(pid, status) => {
                    // PTRACE_TRACESYSGOODを設定し、SIGTRAPと区別する
                    println!("[trace_syscall] stopped : pid={:?}, status={:?}", pid, status);
                    setoptions(pid, Options::PTRACE_O_TRACESYSGOOD).expect("failed setoptions");
                    syscall(pid, None).expect("failed syscall");
                }
                WaitStatus::Signaled(pid, sig, _) => println!("[trace_syscall] recv signal : pid={:?}, sig={:?}", pid, sig),
                WaitStatus::PtraceEvent(pid, sig, _) => println!("[trace_syscall] ptrace event: pid={:?}, sig={:?}", pid, sig),
                WaitStatus::Continued(pid) => println!("[trace_syscall] continued : pid={:?}", pid),
                WaitStatus::StillAlive => println!("[trace_syscall] Still Alive"),
            }
        }
    }

    /// syscall解析
    fn analysis_syscall(&self) {
        // レジスタ出力
        let regs = getregs(self.pid).expect("failed getregs");
        println!(
            "[0x{:x}] {} (rsp=0x{:x} rax=0x{:x} rcx=0x{:x})",
            regs.rip,
            self.to_syscall(regs.orig_rax as i64),
            regs.rsp,
            regs.rax,
            regs.rcx
        );
    }

    /// システムコールNo→システムコール
    fn to_syscall(&self, no: i64) -> &'static str {
        match no {
            libc::SYS_read => "read",
            libc::SYS_write => "write",
            libc::SYS_open => "open",
            libc::SYS_close => "close",
            libc::SYS_stat => "stat",
            libc::SYS_fstat => "fstat",
            libc::SYS_mmap => "mmap",
            libc::SYS_munmap => "munmap",
            libc::SYS_brk => "brk",
            libc::SYS_pread64 => "pread",
            libc::SYS_pwrite64 => "pwrite",
            libc::SYS_readv => "readv",
            libc::SYS_writev => "writev",
            libc::SYS_access => "access",
            libc::SYS_preadv => "preadv",
            libc::SYS_pwritev => "pwritev",
            libc::SYS_mprotect => "mprotect",
            libc::SYS_arch_prctl => "arch_prctl",
            libc::SYS_exit => "exit",
            libc::SYS_exit_group => "exit_group",
            libc::SYS_openat => "openat",
            libc::SYS_clock_nanosleep  => "clock_nanosleep",
            libc::SYS_nanosleep => "nanosleep",
            _ => "unknown system call",
        }
    }
}

