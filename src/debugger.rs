use std::collections::HashMap;
use std::io::{self, Write};
use nix::unistd::{ Pid };
use nix::sys::wait::*;
use nix::sys::ptrace::{ cont, read, write, step, getregs, setregs, kill, AddressType };

use crate::elf::Elf64;
use crate::memory_map::MemoryMap;

// デバッガ
pub struct Debugger {
    pid: Pid,
    path: String,
    address: u64,
    breaklist: HashMap<u64, u64>,
    memory_map: MemoryMap,
    elf: Elf64,
}

/// デバッガ実装
impl Debugger {
    /// コンストラクタ
    pub fn new(pid: Pid, path: String) -> Self {
        Debugger {
            path: path.clone(),
            pid: pid,
            breaklist: HashMap::new(),
            address: 0x0,
            memory_map: MemoryMap::new(pid),
            elf: Elf64::new(path.clone()),
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
                    println!("[start_dbg] exit child process: pid={:?}, sig={:?}", pid, sig);
                    break;
                }
                // シグナル受信による子プロセス停止
                WaitStatus::Stopped(_pid, sig) => self.stopped_handler(sig, first_sig),
                WaitStatus::Signaled(pid, sig, _) => println!("[start_dbg] recv signal : pid={:?}, sig={:?}", pid, sig),
                WaitStatus::PtraceEvent(pid, sig, _) => println!("[start_dbg] ptrace event: pid={:?}, sig={:?}", pid, sig),
                WaitStatus::Continued(pid) => println!("[start_dbg] continued : pid={:?}", pid),
                WaitStatus::StillAlive => println!("[start_dbg] Still Alive"),
                _ => println!("[start_dbg] not support event")
            }
            // 初回のシグナル受信をOFFへ
            first_sig = false;
        }
    }

    /// WaitStatus::Stoppedハンドラ
    fn stopped_handler(&mut self, sig: nix::sys::signal::Signal, first_sig: bool) {
        if true == first_sig {
            // シンボルロード（この段階でロードしないと子プロセスの情報が記載されていない）
            // ※ execvコール後の一発目のシグナル
            let map_info = self.memory_map.load();
            self.address = u64::from_str_radix(&map_info.get(&self.path).unwrap()[0].start_address, 16).unwrap();
            self.elf.load();
        }

        // トレースシグナルであれば処理
        if sig == nix::sys::signal::Signal::SIGTRAP {
            // ブレイクポイントで停止している場合、次の命令を指している
            let bp = self.read_regs().rip - 1;
            if self.is_breakpoint(bp) {
                self.recover_bp(bp);
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
    fn recover_bp(&mut self, bp: u64) {
        // 命令を書き換える
        let org_inst = self.breaklist.get(&bp).unwrap();
        write(self.pid, bp as AddressType, *org_inst as AddressType).expect("recover_bp is failed");

        // ripを元にもどす
        let mut regs = self.read_regs();
        regs.rip = bp;
        self.write_regs(regs);

        // 1STEP実行（元の命令を実行）
        self.step();

        // SIGTRAP待ち
        match nix::sys::wait::waitpid(self.pid, None).expect("recover_bp: wait is failed") {
            // ブレイクポイントの設定をもとにもどす
            WaitStatus::Stopped(_pid, _sig) => self.breakpoint(bp - self.address),
            _ => panic!("recover_bp do not expect event")
        };
    }

    /// ブレイクポイントにヒットするか？
    fn is_breakpoint(&self, rip: u64) -> bool {
        self.breaklist.contains_key(&rip)
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
            let coms: Vec<String> = s.trim().split_whitespace().map(|e| e.parse().ok().unwrap()).collect();

            // 空コマンドは無効
            if coms.len() <= 0 { continue; }

            // 各コマンドを実行
            match &*coms[0] {
                // ブレイクポイント作成
                "b" => self.sh_breakpoint(&coms[1]),
                // ブレイクポイントリリース
                "d" => self.sh_release_break(&coms[1]),
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
                "readregs" => self.show_regs(),
                // 終了
                "quit" => self.sh_quit(),
                _ => println!("not support command: {}", coms[0])
            };
        }
    }

    /// シェルからのブレイクポイント設定
    fn sh_breakpoint(&mut self, sym: &String) {
        // シンボル探索
        let symtbl = self.elf.search_sym(&sym);
        match symtbl {
            Some(s) => {
                // シンボル→アドレス変換したものをブレイクポイント設定
                let addr = s.st_value;
                self.breakpoint(addr);
            }
            _ => println!("not found symbol: {}", sym)
        };
    }

    /// シェルからのブレイクポイントリリース
    fn sh_release_break(&mut self, addr: &String) {
        let addr = u64::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap();
        self.release_break(addr)
    }

    /// シェルからのプログラム停止
    fn sh_quit(&self) {
        kill(self.pid).expect("cannot kill");
        std::process::exit(0);
    }

    /// break point設定
    ///
    /// int 3命令を下位1バイトに埋め込み、ソフトウェア割り込みを発生させる
    fn breakpoint(&mut self, addr: u64) -> u64 {
        println!("Braekpoint at 0x{:x}", addr);

        // int 3命令を埋め込む
        let address = self.address + addr;
        let inst = read(self.pid, address as AddressType).expect("ptrace::read failed");
        let int_code = (0xFFFF_FFFF_FFFF_FF00 & inst as u64) | 0xCC;
        write(self.pid, address as AddressType, int_code as AddressType).expect("ptrace::write failed");

        // アドレスと埋め込み前の命令を保存
        self.breaklist.insert(address, inst as u64);

        return inst as u64;
    }

    /// break point解除
    fn release_break(&mut self, addr: u64) {
        // HashMapからinstractionを取得し、元の命令に書き換える
        let inst = self.breaklist.get(&addr).unwrap();
        println!("release Breakpoint at 0x{:x} (0x{:x})", addr, inst);
        write(self.pid, addr as AddressType, *inst as AddressType).expect("ptrace::write failed");

        // HashMapから登録を削除
        self.breaklist.remove(&addr);
    }

    /// break point表示
    fn show_break(&self) {
        for b in self.breaklist.keys() {
            println!("addr: 0x{:x}", b);
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

    /// レジスタ情報表示
    fn show_regs(&self) {
        println!("{:?}", self.read_regs());
    }

    /// レジスタ読み込み
    fn read_regs(&self) -> libc::user_regs_struct {
        getregs(self.pid).expect("read_regs is failed")
    }

    /// レジスタ書き込み
    fn write_regs(&self, regs: libc::user_regs_struct) {
        setregs(self.pid, regs).expect("write_regs is failed")
    }

    /// ヘルプ表示
    fn help(&self) {
        println!("*************************************************************");
        println!("b [symbol name] : breakpoint at symbol (ex b main)");
        println!("d [no] : delete breakpoint (ex b 1)");
        println!("bl : show breakpoints");
        println!("c : continue program");
        println!("s : step-in");
        println!("readregs : show registers");
        println!("quit : quit program");
        println!("*************************************************************");
    }
}

