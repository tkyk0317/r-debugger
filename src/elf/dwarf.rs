use std::fs::File;
use std::io::{Read, BufReader, Seek, SeekFrom, Result, Error, ErrorKind};

use crate::elf::elf::ElfSecHeader;

/// debug_info header(32bit mode)
#[derive(Debug)]
struct DebugInfoHeader {
    len: u32,            // debug_info length(for 32bit dwarf format. 0xFFFF_FFFF when 64bit dwarf mode)
    actual_len: u64,     // debug_info length(for 64bit mode)
    version: u16,        // dwarf version
    abb_rev_offset: u32, // debug_abbrev section offset in .debug_abbrev
    address_size: u8,    // 1-byte unsigned integer representing the size in bytes of an address on the target architecture(pointer size)
}

impl DebugInfoHeader {
    /// コンストラクタ
    pub fn new() -> Self {
        DebugInfoHeader {
            len: 0,
            actual_len: 0,
            version: 0,
            abb_rev_offset: 0,
            address_size: 0
        }
    }

    /// ヘッダー表示
    #[allow(dead_code)]
    pub fn show(&self) {
        println!(".debug_info header:");
        println!("    length      : 0x{:x}", self.len);
        println!("    version     : 0x{:x}", self.version);
        println!("    abb offset  : 0x{:x}", self.abb_rev_offset);
        println!("    address size: 0x{:x}", self.address_size);
    }
}

/// debug_infoセクション
#[derive(Debug)]
struct DebugInfoSec {
    header: DebugInfoHeader,
}

impl DebugInfoSec {
    /// コンストラクタ
    pub fn new() -> Self {
        DebugInfoSec {
            header: DebugInfoHeader::new()
        }
    }
}

/// Dwarf情報
pub struct Dwarf {
    debug_info: DebugInfoSec,
}

impl Dwarf {
    /// コンストラクタ
    pub fn new() -> Self {
        Dwarf {
            debug_info: DebugInfoSec::new(),
        }
    }

    /// debug_infoロード
    pub fn load(&mut self, path: &str, header: &[ElfSecHeader]) -> Result<()> {
        // debug_infoセクションを探す
        let debug_info_sec = match self.search_debug_info_sec(&header) {
            Some(h) => h,
            _ => return Err(Error::new(ErrorKind::NotFound, "Not found debug_info section header"))
        };

        // debug_infoセクションをロード
        let f = File::open(&path)?;
        let mut reader = BufReader::new(f);
        self.load_debug_info(&mut reader, &debug_info_sec)?;

        Ok(())
    }

    /// search debug_info section
    fn search_debug_info_sec<'a>(&self, header: &'a [ElfSecHeader]) -> Option<&'a ElfSecHeader> {
        header.iter().find(|s| s.get_name() == ".debug_info")
    }

    /// debug_info sectionロード
    fn load_debug_info(&mut self, reader: &mut BufReader<File>, sec_header: &ElfSecHeader) -> Result<()> {
        // debug_infoセクションへ移動
        reader.seek(SeekFrom::Start(sec_header.get_offset()))?;

        // len
        let mut word = [0; 4];
        reader.read_exact(&mut word)?;
        self.debug_info.header.len = u32::from_le_bytes(word);

        // load actual len when 64bit mode
        if self.debug_info.header.len == 0xFFFF_FFFF { // 64bit mode
            let mut word64 = [0; 8];
            reader.read_exact(&mut word64)?;
            self.debug_info.header.actual_len = u64::from_le_bytes(word64);
        }

        // version
        let mut half_word = [0; 2];
        reader.read_exact(&mut half_word)?;
        self.debug_info.header.version = u16::from_le_bytes(half_word);

        // abb_rev offset
        reader.read_exact(&mut word)?;
        self.debug_info.header.abb_rev_offset = u32::from_le_bytes(word);

        // address size
        let mut byte = [0; 1];
        reader.read_exact(&mut byte)?;
        self.debug_info.header.address_size = u8::from_le_bytes(byte);

        Ok(())
    }
}
