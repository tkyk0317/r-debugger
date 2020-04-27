use std::env;
use std::fs;
use std::path::Path;
use std::ffi::{ CString };
use nix::sys::ptrace::{ traceme };
use nix::unistd::{fork, ForkResult, execv};

mod debugger;
mod stracer;
mod memory_map;
mod elf;
use debugger::Debugger;
use stracer::Tracer;

/// メイン処理
///
/// rtracer [option] [filename]
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        panic!("arg len is not two");
    }

    let path = &args[2];
    if false == Path::new(path).exists() {
        panic!("file not exist: {}", path);
    }

    // 子プロセス生成
    match fork() {
        Ok(ForkResult::Parent { child }) => {
            if "trace" == args[1] {
                let tracer = Tracer::new(child);
                tracer.start();
            }
            else {
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
        Err(_) => println!("Fork failed")
    }
}

/// 子プロセス実行
fn child(path: &str) {
    // 自身をトレース対象とする
    traceme().expect("faield traceme");

    let options = [];
    let path = CString::new(path).unwrap();
    execv(&path, &options).expect("execv is failed");
}

