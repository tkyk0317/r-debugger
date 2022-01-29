mod address;
mod debugger;
mod elf;
mod memory_map;
mod stracer;

use crate::debugger::Debugger;
use crate::stracer::Tracer;
use nix::sys::ptrace::traceme;
use nix::unistd::{execv, fork, ForkResult};
use std::env;
use std::ffi::CString;
use std::fs;
use std::path::Path;

/// メイン処理
///
/// rtracer [option] [filename]
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        panic!("arg len is not two");
    }

    let path = &args[2];
    if !Path::new(path).exists() {
        panic!("file not exist: {}", path);
    }

    // 子プロセス生成
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            if "trace" == args[1] {
                let tracer = Tracer::new(child);
                tracer.start();
            } else {
                let abs_path = fs::canonicalize(path.to_string())
                    .expect("failed fs::canonicalize")
                    .as_path()
                    .to_str()
                    .unwrap()
                    .to_string();
                let mut dbg = Debugger::new(child, abs_path);
                dbg.start();
            }
        }
        Ok(ForkResult::Child) => child(path),
        Err(_) => println!("Fork failed"),
    }
}

/// 子プロセス実行
fn child(path: &str) {
    // 自身をトレース対象とする
    traceme().expect("failed traceme");

    let path = CString::new(path).unwrap();
    execv(&path, &[path.clone()]).expect("execv is failed");
}
