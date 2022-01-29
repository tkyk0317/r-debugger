use nix::sys::ptrace::{cont, getregs, kill, read, setregs, step, write, AddressType};
use nix::sys::wait::*;
use nix::unistd::Pid;
use std::io::{self, Result, Write};

use crate::address::{AddressTrait, AdrFromAbs, AdrFromRel};
use crate::elf::elf64::Elf64;
use crate::memory_map::MemoryMap;

// ブレイクポイントリスト
struct Breakpoint<'a> {
    sym: String,                      // ブレイクポイントを貼るシンボル名
    inst: usize,                      // ブレイクポイント箇所の命令列
    addr: Box<dyn AddressTrait + 'a>, // シンボルテーブルに記載されているアドレス
}

// ブレイクポイント管理
struct BreakpointList<'a> {
    breakpoints: Vec<Breakpoint<'a>>,
}

/// ブレイクポイント管理strcut実装
impl<'a> BreakpointList<'a> {
    /// コンストラクタ
    pub fn new() -> Self {
        BreakpointList {
            breakpoints: vec![],
        }
    }

    /// ブレイクポイント設定取得
    pub fn get(&self) -> &Vec<Breakpoint> {
        &self.breakpoints
    }

    /// ブレイクポイント登録
    pub fn register<T: 'a + AddressTrait>(&mut self, sym: &str, bp: T, bp_inst: usize) -> bool {
        // 既に登録されている場合、登録しない
        match self.breakpoints.iter().find(|b| b.addr.get() == bp.get()) {
            Some(_) => false,
            None => {
                // ブレイクポイント登録
                self.breakpoints.push({
                    Breakpoint {
                        sym: sym.to_string(),
                        addr: Box::new(bp),
                        inst: bp_inst,
                    }
                });
                true
            }
        }
    }

    /// アドレスが登録されているか
    pub fn has_addr<T: AddressTrait>(&self, addr: &T) -> bool {
        self.search(addr).is_some()
    }

    /// ブレイクポイントサーチ
    pub fn search<T: AddressTrait>(&self, addr: &T) -> Option<&Breakpoint> {
        self.breakpoints.iter().find(|b| b.addr.get() == addr.get())
    }

    /// ブレイクポイント削除
    ///
    /// 削除したブレイクポイントを返す
    pub fn delete(&mut self, index: usize) -> Option<Breakpoint> {
        // インデックス外はエラー
        let l = self.breakpoints.len();
        if l == 0 || index >= l {
            return None;
        }

        // ブレイクポイント削除
        Some(self.breakpoints.remove(index))
    }
}

// デバッガ
pub struct Debugger<'a> {
    pid: Pid,
    path: String,
    entry: usize, // エントリーアドレス
    breakpoint: BreakpointList<'a>,
    memory_map: MemoryMap,
    elf: Elf64,
}

/// デバッガ実装
impl<'a> Debugger<'a> {
    /// コンストラクタ
    pub fn new(target_pid: Pid, path: String) -> Self {
        Debugger {
            path: path.clone(),
            pid: target_pid,
            entry: 0x0,
            breakpoint: BreakpointList::new(),
            memory_map: MemoryMap::new(target_pid),
            elf: Elf64::new(path),
        }
    }

    /// デバッガ起動
    pub fn start(&mut self) {
        println!("start start_dbg({})", self.pid);

        // 子プロセスWait
        let mut first_sig = true;
        loop {
            match nix::sys::wait::waitpid(self.pid, None).expect("wait child process failed") {
                // シグナル受信による子プロセス終了
                WaitStatus::Exited(pid, sig) => {
                    println!(
                        "[start_dbg] exit child process: pid={:?}, sig={:?}",
                        pid, sig
                    );
                    break;
                }
                // シグナル受信による子プロセス停止
                WaitStatus::Stopped(_pid, sig) => {
                    if first_sig {
                        // シンボルロード（この段階でロードしないと子プロセスの情報が記載されていない）
                        // ※ execvコール後の一発目のシグナル
                        if let Err(err) = self.load_elf() {
                            println!("cannot parse ELF: {:?}", err);
                            self.sh_quit();
                        }
                    }
                    self.stopped_handler(sig);
                }
                WaitStatus::Signaled(pid, sig, _) => {
                    println!("[start_dbg] recv signal : pid={:?}, sig={:?}", pid, sig)
                }
                WaitStatus::PtraceEvent(pid, sig, _) => {
                    println!("[start_dbg] ptrace event: pid={:?}, sig={:?}", pid, sig)
                }
                WaitStatus::Continued(pid) => println!("[start_dbg] continued : pid={:?}", pid),
                WaitStatus::StillAlive => println!("[start_dbg] Still Alive"),
                _ => println!("[start_dbg] not support event"),
            }
            // 初回のシグナル受信をOFFへ
            first_sig = false;
        }
    }

    /// ELFファイルロード
    fn load_elf(&mut self) -> Result<()> {
        // 対象プログラムのロード先先頭アドレスを取得
        let map_info = self.memory_map.load();
        self.entry = usize::from_str_radix(
            &map_info
                .get(&self.path)
                .expect("can not read entry address")[0]
                .start_address,
            16,
        )
        .expect("can not parse entry ddress");

        // ELFファイルロード
        self.elf.load()
    }

    /// WaitStatus::Stoppedハンドラ
    fn stopped_handler(&mut self, sig: nix::sys::signal::Signal) {
        // トレースシグナルであれば処理
        if sig == nix::sys::signal::Signal::SIGTRAP {
            // ブレイクポイントで停止している場合、次の命令を指している
            let rip = (self.read_regs().rip - 1) as usize;
            let bp = AdrFromAbs::new(rip);
            if self.breakpoint.has_addr(&bp) {
                self.recover_bp(&bp);
                println!("break at 0x{:x}", bp.get());
            }

            // シェルから入力を受け付ける
            self.shell();
        }
    }

    /// ブレイクポイントで止まった後のリカバー処理
    ///
    /// 1. ブレイクポイントで止まった部分の命令を元の命令に書き換え
    /// 2. ripをブレイクポイントのアドレスへ再設定
    /// 3. 1step実行し、元の命令を処理
    /// 4. SIGTRAPを待ち、1で書き換えたブレイクポイントを貼る
    fn recover_bp<T: AddressTrait>(&mut self, rip_bp: &T) {
        // 命令を書き換える
        let bp_info = self.breakpoint.search(rip_bp).unwrap();

        // 引数にripが指定されているので、baseアドレスはゼロ
        self.write_mem(rip_bp, bp_info.inst);

        // ripを元にもどす
        let mut regs = self.read_regs();
        regs.rip = rip_bp.get() as u64;
        self.write_regs(regs);

        // 1STEP実行（元の命令を実行）
        self.step();

        // SIGTRAP待ち
        match nix::sys::wait::waitpid(self.pid, None).expect("recover_bp: wait is failed") {
            // ブレイクポイントの設定をもとにもどす
            WaitStatus::Stopped(_, _) => {
                // 登録する際に、エントリーアドレス分を加算しているので、差し引く
                let addr = bp_info.addr.get();
                let sym = bp_info.sym.clone();
                self.breakpoint(self.to_sym_addr(addr), &sym);
            }
            _ => panic!("recover_bp do not expect event"),
        };
    }

    /// 入力待ち
    fn shell(&mut self) {
        loop {
            // プロンプトを表示
            let regs = self.read_regs();
            print!("[rip: 0x{:x}] >> ", regs.rip);
            io::stdout().flush().unwrap();

            // コマンド入力受付
            let mut s = String::new();
            std::io::stdin().read_line(&mut s).ok();
            let coms: Vec<String> = s
                .trim()
                .split_whitespace()
                .map(|e| e.parse().ok().unwrap())
                .collect();

            // 空コマンドは無効
            if coms.is_empty() {
                continue;
            }

            // 各コマンドを実行
            match &*coms[0] {
                // ブレイクポイント作成
                "b" if coms.len() == 2 => self.sh_breakpoint(&coms[1]),
                // ブレイクポイントリリース
                "d" if coms.len() == 2 => self.sh_release_break(&coms[1]),
                // シンボルリード
                "p" if coms.len() == 2 => self.sh_read_sym(&coms[1]),
                // シンボル書き込み
                "set" if coms.len() == 4 && "var" == coms[1] => {
                    self.sh_write_sym(&coms[2], &coms[3])
                }
                // 再開
                "c" => {
                    self.cont();
                    break;
                }
                // STEP実行
                "s" => {
                    self.step();
                    break;
                }
                // ヘルプ
                "h" => self.help(),
                // ブレイクポイント表示
                "bl" => self.show_break(),
                // レジスタ表示
                "info" if coms.len() == 2 && "regs" == coms[1] => self.show_regs(),
                // debugセクション情報表示
                "info" if coms.len() == 2 && "debugsec" == coms[1] => self.elf.show_debug(),
                // レジスタ書き込み
                "set" if coms.len() == 4 && "regs" == coms[1] => self.set_regs(&coms[2], &coms[3]),
                // 終了
                "quit" => self.sh_quit(),
                _ => println!("not support command: {}", coms[0]),
            };
        }
    }

    /// シェルからのブレイクポイント設定
    fn sh_breakpoint(&mut self, sym: &str) {
        // シンボル探索
        match self.elf.search_func_sym(sym) {
            Some(s) => {
                // シンボル→アドレス変換したものをブレイクポイント設定
                let addr = s.st_value;
                self.breakpoint(addr as usize, sym);
                println!("BreakPoint at 0x{:x}", addr);
            }
            _ => println!("not found symbol: {}", sym),
        };
    }

    /// シェルからのブレイクポイントリリース
    fn sh_release_break(&mut self, no: &str) {
        let ret = self.release_break(no.parse::<usize>().unwrap());
        if ret {
            println!("release Breakpoint({})", no);
        }
    }

    /// シェルからのシンボルリード
    fn sh_read_sym(&self, sym: &str) {
        // シンボル探索
        match self.elf.search_var_sym(sym) {
            Some(s) => {
                // シンボルの内容を表示
                let addr = AdrFromRel::new(self.entry, s.st_value as usize);
                println!("0x{:x}", self.read_mem(&addr));
            }
            _ => println!("not found symbol: {}", sym),
        };
    }

    /// シェルからのシンボル書き込み
    fn sh_write_sym(&self, sym: &str, val: &str) {
        let val = match usize::from_str_radix(val.trim_start_matches("0x"), 16) {
            Ok(v) => v,
            _ => {
                println!("parse error: {}", val);
                return;
            }
        };

        // シンボル探索
        match self.elf.search_var_sym(sym) {
            Some(s) => {
                // シンボルの内容を書き換え
                let addr = AdrFromRel::new(self.entry, s.st_value as usize);
                self.write_mem(&addr, val);
            }
            _ => println!("not found symbol: {}", sym),
        };
    }

    /// シェルからのプログラム停止
    fn sh_quit(&self) {
        kill(self.pid).expect("cannot kill");
        std::process::exit(0);
    }

    /// break point設定
    ///
    /// int 3命令を下位1バイトに埋め込み、ソフトウェア割り込みを発生させる
    fn breakpoint(&mut self, addr: usize, sym: &str) {
        // ブレイクポイント設定
        let address = AdrFromRel::new(self.entry, addr);

        // int 3命令を埋め込む
        let inst = self.read_mem(&address);
        let int_code = (0xFFFF_FFFF_FFFF_FF00 & inst as u64) | 0xCC;
        self.write_mem(&address, int_code as usize);

        // ブレイクポイント登録
        self.breakpoint.register(sym, address, inst as usize);
    }

    /// break point解除
    ///
    /// 指定されたインデックスに存在するブレイクポイントを削除
    fn release_break(&mut self, index: usize) -> bool {
        // ブレイクポイントを削除し、元の命令に書き換える
        let bp = self.breakpoint.delete(index);
        match bp {
            Some(bp) => {
                // 命令を元にもどす
                unsafe {
                    write(
                        self.pid,
                        bp.addr.get() as AddressType,
                        bp.inst as AddressType,
                    )
                    .expect("ptrace::write failed");
                }
                true
            }
            None => false,
        }
    }

    /// break point表示
    fn show_break(&self) {
        let bps = self.breakpoint.get();
        if bps.is_empty() {
            println!("not entried breakpoint");
        } else {
            for (i, b) in self.breakpoint.get().iter().enumerate() {
                println!(
                    "{}: {} (0x{:016x})",
                    i,
                    b.sym,
                    self.to_sym_addr(b.addr.get())
                );
            }
        }
    }

    /// ptrace cont実行
    fn cont(&self) {
        cont(self.pid, None).expect("pcont is failed");
        println!("continue...");
    }

    /// ステップ実行
    fn step(&self) {
        step(self.pid, None).expect("step is failed");
    }

    /// レジスタ情報設定
    ///
    /// レジスタ名と16進数を受け取り、レジスタへデータを設定する
    fn set_regs(&self, reg: &str, val: &str) {
        let val = match u64::from_str_radix(val.trim_start_matches("0x"), 16) {
            Ok(v) => v,
            _ => {
                println!("parse error: {}", val);
                return;
            }
        };

        // 存在しているレジスタの値を更新
        let mut regs = self.read_regs();
        match reg {
            "orig_rax" => regs.orig_rax = val,
            "rip" => regs.rip = val,
            "rsp" => regs.rsp = val,
            "r15" => regs.r15 = val,
            "r14" => regs.r14 = val,
            "r13" => regs.r13 = val,
            "r12" => regs.r12 = val,
            "r11" => regs.r11 = val,
            "r10" => regs.r10 = val,
            "r9" => regs.r9 = val,
            "r8" => regs.r8 = val,
            "rax" => regs.rax = val,
            "rcx" => regs.rcx = val,
            "rdx" => regs.rdx = val,
            "rsi" => regs.rsi = val,
            "rdi" => regs.rdi = val,
            "cs" => regs.cs = val,
            "eflags" => regs.eflags = val,
            "ss" => regs.ss = val,
            "fs_base" => regs.fs_base = val,
            "gs_base" => regs.gs_base = val,
            "ds" => regs.ds = val,
            "es" => regs.es = val,
            "fs" => regs.fs = val,
            "gs" => regs.gs = val,
            _ => {
                println!("not register {}", reg);
                return;
            }
        };

        // レジスタへ書き込み
        self.write_regs(regs);
    }

    /// レジスタ情報表示
    fn show_regs(&self) {
        let regs = self.read_regs();
        println!("orig_rax: 0x{:016x}", regs.orig_rax);
        println!("rip     : 0x{:016x}", regs.rip);
        println!("rsp     : 0x{:016x}", regs.rsp);
        println!("r15     : 0x{:016x}", regs.r15);
        println!("r14     : 0x{:016x}", regs.r14);
        println!("r13     : 0x{:016x}", regs.r13);
        println!("r12     : 0x{:016x}", regs.r12);
        println!("r11     : 0x{:016x}", regs.r11);
        println!("r10     : 0x{:016x}", regs.r10);
        println!("r9      : 0x{:016x}", regs.r9);
        println!("r8      : 0x{:016x}", regs.r8);
        println!("rax     : 0x{:016x}", regs.rax);
        println!("rcx     : 0x{:016x}", regs.rcx);
        println!("rdx     : 0x{:016x}", regs.rdx);
        println!("rsi     : 0x{:016x}", regs.rsi);
        println!("rdi     : 0x{:016x}", regs.rdi);
        println!("cs      : 0x{:016x}", regs.cs);
        println!("eflags  : 0x{:016x}", regs.eflags);
        println!("ss      : 0x{:016x}", regs.ss);
        println!("fs_base : 0x{:016x}", regs.fs_base);
        println!("gs_base : 0x{:016x}", regs.gs_base);
        println!("ds      : 0x{:016x}", regs.ds);
        println!("es      : 0x{:016x}", regs.es);
        println!("fs      : 0x{:016x}", regs.fs);
        println!("gs      : 0x{:016x}", regs.gs);
    }

    /// レジスタ読み込み
    fn read_regs(&self) -> libc::user_regs_struct {
        getregs(self.pid).expect("read_regs is failed")
    }

    /// レジスタ書き込み
    fn write_regs(&self, regs: libc::user_regs_struct) {
        setregs(self.pid, regs).expect("write_regs is failed")
    }

    /// メモリ読み込み
    fn read_mem<T: AddressTrait>(&self, addr: &T) -> u64 {
        read(self.pid, addr.get() as AddressType).expect("ptrace::read is failed") as u64
    }

    /// メモリ書き込み
    fn write_mem<T: AddressTrait>(&self, addr: &T, val: usize) {
        unsafe {
            write(self.pid, addr.get() as AddressType, val as AddressType)
                .expect("ptrace::write is failed");
        }
    }

    /// ヘルプ表示
    fn help(&self) {
        println!("******************************************************************************");
        println!("b [symbol name]                 : breakpoint at symbol (ex b main)");
        println!("d [no]                          : delete breakpoint (ex b 1)");
        println!("bl                              : show breakpoints");
        println!("info regs                       : show registers");
        println!("info debugsec                   : show debug section(.debug_info)");
        println!("c                               : continue program");
        println!("s                               : step-in");
        println!("p [symbol name]                 : show symbol variable (ex p global_variable)");
        println!("set regs [register] [value]     : write registers (ex set regs rax 0x1000)");
        println!("set var [variable name] [value] : write variable (ex set var g_var 0x1000)");
        println!("quit                            : quit program");
        println!("******************************************************************************");
    }

    /// アドレス変換
    ///
    /// ロードされているアドレスから、シンボルテーブルに記載されているアドレスへ変換
    fn to_sym_addr(&self, addr: usize) -> usize {
        addr - self.entry
    }
}
