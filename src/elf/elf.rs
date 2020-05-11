use std::fs::File;
use std::io::{Read, BufReader, SeekFrom, Seek, Result, Error, ErrorKind};
use symbolic_demangle::{ demangle };

use super::dwarf::Dwarf;

type Elf64Half = u16;
type Elf64Word = u32;
type Elf64Addr = u64;
type Elf64Offset = u64;
type Elf64Xword = u64;

const IDENT_SIZE: usize = 16;
const MASK_ST_TYPE: u8 = 0x0F;
const MASK_ST_BIND: u8 = 0xF0;
const SHIFT_ST_BIND: u8 = 0x04;

// ELFヘッダー
#[derive(Debug)]
struct ElfHeader {
    e_ident: [u8; IDENT_SIZE],
    e_type: Elf64Half,
    e_machine: Elf64Half,
    e_version: Elf64Word,
    e_entry: Elf64Addr,
    e_phoff: Elf64Offset,
    e_shoff: Elf64Offset,
    e_flags: Elf64Word,
    e_ehsize: Elf64Half,
    e_phentsize: Elf64Half,
    e_phnum: Elf64Half,
    e_shentsize: Elf64Half,
    e_shnum: Elf64Half,
    e_shstrndx: Elf64Half,
}

/// ELFヘッダー
impl ElfHeader {
    /// コンストラクタ
    pub fn new() -> Self {
        ElfHeader {
            e_ident: [0; IDENT_SIZE],
            e_type: 0,
            e_machine: 0,
            e_version: 0,
            e_entry: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 0,
            e_phentsize: 0,
            e_phnum: 0,
            e_shentsize: 0,
            e_shnum: 0,
            e_shstrndx: 0,
        }
    }
}

// ELFプログラムヘッダー
#[derive(Debug,Clone)]
struct ElfProgHeader {
  p_type: Elf64Word,
  p_flags: Elf64Word,
  p_offset: Elf64Offset,
  p_vaddr: Elf64Addr,
  p_paddr: Elf64Addr,
  p_filesz: Elf64Xword,
  p_memsz: Elf64Xword,
  p_align: Elf64Xword,
}

/// ELFプログラムヘッダー
impl ElfProgHeader {
    /// コンストラクタ
    pub fn new() -> Self {
        ElfProgHeader {
            p_type: 0,
            p_flags: 0,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 0,
            p_align: 0,
        }
    }
}

// ELFセクションヘッダー
#[derive(Debug,Clone)]
pub struct ElfSecHeader {
    sh_name: Elf64Word,
    sh_type: Elf64Word,
    sh_flags: Elf64Xword,
    sh_addr: Elf64Addr,
    sh_offset: Elf64Offset,
    sh_size: Elf64Xword,
    sh_link: Elf64Word,
    sh_info: Elf64Word,
    sh_addralign: Elf64Xword,
    sh_entsize: Elf64Xword,
    sh_no: Elf64Half, // セクション番号（管理のため追加）
    sh_rname: String, // セクション名
}

impl ElfSecHeader {
    /// セクション名取得
    pub fn get_name(&self) -> &str { &self.sh_rname }
    /// セクションオフセット取得
    pub fn get_offset(&self) -> Elf64Offset { self.sh_offset }
    /// サイズ取得
    pub fn get_size(&self) -> Elf64Xword { self.sh_size }
}

// SH Type
#[derive(PartialEq)]
enum ShType {
    Null,    // 0
    Progbit, // 1
    ShmTab,  // 2
    StrTab,  // 3
    Rela,    // 4
    Hash,    // 5
    Dynamic, // 6
    Note,    // 7
    Nobits,  // 8
    Rel,     // 9
    Shlib,   // 10
    DynSym,  // 11
    LoProc,  // 0x7000_0000
    HiProc,  // 0x7FFF_FFFF
    LoUser,  // 0x8000_0000
    HiUser,  // 0x8FFF_FFFF
    Unknown,
}

/// ELFセクションヘッダー
impl ElfSecHeader {
    // コンストラクタ
    pub fn new() -> Self {
        ElfSecHeader {
            sh_name: 0,
            sh_type: 0,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: 0,
            sh_size: 0,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
            sh_no: 0,
            sh_rname: "".to_string(),
        }
    }
}

// シンボルbind
#[derive(Debug,Clone,PartialEq)]
enum StBind {
    Unknown, // 初期値
    Local,   // 0
    Global,  // 1
    Weak,    // 2
}

// シンボルType
#[derive(Debug,Clone,PartialEq)]
enum StType {
    Unknown,  // 初期値
    Notype,   // 0
    Object,   // 1
    Func,     // 2
}

// シンボルテーブル
#[derive(Debug,Clone)]
pub struct SymTbl {
    st_name: Elf64Word,
    st_info: u8,
    st_other: u8,
    st_shndx: Elf64Half,
    pub st_value: Elf64Addr,
    st_size: Elf64Xword,
    st_rname: String, // strtabから読み取ったシンボル名（管理上の為、追加）
    st_bind: StBind,  // st_infoの上位4bits
    st_type: StType,  // st_infoの下位4bits
}

/// シンボルテーブル
impl SymTbl {
    /// コンストラクタ
    fn new() -> Self {
        SymTbl {
            st_name: 0,
            st_info: 0,
            st_other: 0,
            st_shndx: 0,
            st_value: 0,
            st_size: 0,
            st_rname: "".to_string(),
            st_bind: StBind::Unknown,
            st_type: StType::Unknown,
        }
    }
}

// ELFデータ
pub struct Elf64 {
    path: String,
    header: ElfHeader,
    prog_header: Vec<ElfProgHeader>,
    sec_header: Vec<ElfSecHeader>,
    sym_tbl: Vec<SymTbl>,
    dwarf: Dwarf,
}

/// ELF解析
impl Elf64 {
    /// コンストラクタ
    pub fn new(filepath: String) -> Self {
        Elf64 {
            path: filepath,
            header: ElfHeader::new(),
            prog_header: vec![],
            sec_header: vec![],
            sym_tbl: vec![],
            dwarf: Dwarf::new(),
        }
    }

    /// debugセクション情表示
    pub fn show_debug(&self) {
        self.dwarf.show();
    }

    /// ELFデータロード
    pub fn load(&mut self) -> Result<()> {
        // ELFヘッダーロード
        let f = File::open(&self.path)?;
        let mut reader = BufReader::new(f);
        self.load_elf_header(&mut reader)?;

        // プログラムヘッダーロード
        self.load_prog_header(&mut reader)?;

        // セクションヘッダーロード
        self.load_sec_header(&mut reader)?;

        // シンボルテーブルロード
        self.load_symtab(&mut reader)?;

        // dwarf情報読み込み
        self.dwarf.load(&self.path, &self.sec_header)?;

        Ok(())
    }

    /// Functionシンボルサーチ
    pub fn search_func_sym(&self, sym_name: &str) -> Option<&SymTbl> {
        self.sym_tbl.iter().find(|sym| {
            *sym_name == demangle(&sym.st_rname) && sym.st_type == StType::Func
        })
    }

    /// Variableシンボルサーチ
    pub fn search_var_sym(&self, sym_name: &str) -> Option<&SymTbl> {
        self.sym_tbl.iter().find(|sym| {
            *sym_name == demangle(&sym.st_rname) && sym.st_type == StType::Object
        })
    }

    /// ELFヘッダー読み込み
    fn load_elf_header(&mut self, reader: &mut BufReader<File>) -> Result<()> {
        // e_ident
        reader.read_exact(&mut self.header.e_ident)?;

        // e_type
        let mut half_word = [0; 2];
        reader.read_exact(&mut half_word)?;

        // e_machine
        reader.read_exact(&mut half_word)?;
        self.header.e_machine = u16::from_le_bytes(half_word);

        // e_version
        let mut word = [0; 4];
        reader.read_exact(&mut word)?;
        self.header.e_version = u32::from_le_bytes(word);

        // e_entry
        let mut word64 = [0; 8];
        reader.read_exact(&mut word64)?;
        self.header.e_entry = u64::from_le_bytes(word64);

        // e_phoff
        reader.read_exact(&mut word64)?;
        self.header.e_phoff = u64::from_le_bytes(word64);

        // e_shoff
        reader.read_exact(&mut word64)?;
        self.header.e_shoff = u64::from_le_bytes(word64);

        // e_flags
        reader.read_exact(&mut word)?;
        self.header.e_flags = u32::from_le_bytes(word);

        // e_ehsize
        reader.read_exact(&mut half_word)?;
        self.header.e_ehsize = u16::from_le_bytes(half_word);

        // e_phentsize
        reader.read_exact(&mut half_word)?;
        self.header.e_phentsize = u16::from_le_bytes(half_word);

        // e_phnum
        reader.read_exact(&mut half_word)?;
        self.header.e_phnum = u16::from_le_bytes(half_word);

        // e_shentsize
        reader.read_exact(&mut half_word)?;
        self.header.e_shentsize = u16::from_le_bytes(half_word);

        // e_shnum
        reader.read_exact(&mut half_word)?;
        self.header.e_shnum = u16::from_le_bytes(half_word);

        // e_shstrndx
        reader.read_exact(&mut half_word)?;
        self.header.e_shstrndx = u16::from_le_bytes(half_word);

        // プログラムヘッダー、セクションヘッダー数が判明したので、リサイズ
        self.prog_header.resize(self.header.e_phnum as usize, ElfProgHeader::new());
        self.sec_header.resize(self.header.e_shnum as usize, ElfSecHeader::new());

        Ok(())
    }

    /// プログラムヘッダーロード
    fn load_prog_header(&mut self, reader: &mut BufReader<File>) -> Result<()> {
        // プログラムヘッダー位置へSeek
        reader.seek(SeekFrom::Start(self.header.e_phoff))?;

        for i in 0..self.header.e_phnum {
            // p_type
            let mut word = [0; 4];
            reader.read_exact(&mut word)?;
            self.prog_header[i as usize].p_type = u32::from_le_bytes(word);

            // p_flags
            reader.read_exact(&mut word)?;
            self.prog_header[i as usize].p_flags = u32::from_le_bytes(word);

            // p_flags
            let mut word64 = [0; 8];
            reader.read_exact(&mut word64)?;
            self.prog_header[i as usize].p_offset = u64::from_le_bytes(word64);

            // p_vaddr
            reader.read_exact(&mut word64)?;
            self.prog_header[i as usize].p_vaddr = u64::from_le_bytes(word64);

            // p_paddr
            reader.read_exact(&mut word64)?;
            self.prog_header[i as usize].p_paddr = u64::from_le_bytes(word64);

            // p_memsz
            reader.read_exact(&mut word64)?;
            self.prog_header[i as usize].p_memsz = u64::from_le_bytes(word64);

            // p_align
            reader.read_exact(&mut word64)?;
            self.prog_header[i as usize].p_align = u64::from_le_bytes(word64);
        }
        Ok(())
    }

    /// セクションヘッダーロード
    fn load_sec_header(&mut self, reader: &mut BufReader<File>) -> Result<()> {
        // セクションヘッダー位置へSeek
        reader.seek(SeekFrom::Start(self.header.e_shoff))?;

        for i in 0..self.header.e_shnum {
            // sh_name
            let mut word = [0; 4];
            reader.read_exact(&mut word)?;
            self.sec_header[i as usize].sh_name = u32::from_le_bytes(word);

            // sh_type
            reader.read_exact(&mut word)?;
            self.sec_header[i as usize].sh_type = u32::from_le_bytes(word);

            // sh_flags
            let mut word64 = [0; 8];
            reader.read_exact(&mut word64)?;
            self.sec_header[i as usize].sh_flags = u64::from_le_bytes(word64);

            // sh_addr
            reader.read_exact(&mut word64)?;
            self.sec_header[i as usize].sh_addr = u64::from_le_bytes(word64);

            // sh_offset
            reader.read_exact(&mut word64)?;
            self.sec_header[i as usize].sh_offset = u64::from_le_bytes(word64);

            // sh_size
            reader.read_exact(&mut word64)?;
            self.sec_header[i as usize].sh_size = u64::from_le_bytes(word64);

            // sh_link
            reader.read_exact(&mut word)?;
            self.sec_header[i as usize].sh_link = u32::from_le_bytes(word);

            // sh_info
            reader.read_exact(&mut word)?;
            self.sec_header[i as usize].sh_info = u32::from_le_bytes(word);

            // sh_addralign
            reader.read_exact(&mut word64)?;
            self.sec_header[i as usize].sh_addralign= u64::from_le_bytes(word64);

            // sh_entsize
            reader.read_exact(&mut word64)?;
            self.sec_header[i as usize].sh_entsize = u64::from_le_bytes(word64);

            // セクション番号としてインデックスを設定
            // ※ セクション番号はセクションの並び順序と等しい
            self.sec_header[i as usize].sh_no = i;
        }

        // セクション名を埋める
        let strtab_buf = self.read_strtab_of_sec(reader)?;
        for i in 0..self.header.e_shnum {
            // 実際のセクション名をstrtabセクションからリード
            let offset = self.sec_header[i as usize].sh_name as usize;
            self.sec_header[i as usize].sh_rname = self.to_string(&strtab_buf, offset);
        }

        Ok(())
    }

    /// シンボルテーブルロード
    fn load_symtab(&mut self, reader: &mut BufReader<File>) -> Result<()> {
        // strtab情報をリード(Seekされているので注意)
        let strtab_buf = self.read_strtab(reader)?;

        // symtab位置までSeek
        let symtab = match
            self.sec_header
                .iter()
                .filter(|s| self.to_shtype(s.sh_type) == ShType::ShmTab)
                .collect::<Vec<&ElfSecHeader>>()
                .pop() {
            Some(header) => header,
            _ => return Err(Error::new(ErrorKind::NotFound, "Not found symtab"))
        };
        reader.seek(SeekFrom::Start(symtab.sh_offset))?;

        // sym_tblリサイズ
        let count = (symtab.sh_size / symtab.sh_entsize) as usize;
        self.sym_tbl.resize(count, SymTbl::new());

        // すべてのシンボルをロード
        for i in 0..count {
            // st_name
            let mut word = [0; 4];
            reader.read_exact(&mut word)?;
            let offset = u32::from_le_bytes(word);
            self.sym_tbl[i].st_name = offset;

            // 実際のシンボル名をstrtabセクションからリード
            self.sym_tbl[i].st_rname = self.to_string(&strtab_buf, offset as usize);

            // st_info
            let mut c = [0; 1];
            reader.read_exact(&mut c)?;
            self.sym_tbl[i].st_info = u8::from_le_bytes(c);

            // st_infoから各Bind・Typeを算出
            self.sym_tbl[i].st_type = self.to_st_type(self.sym_tbl[i].st_info);
            self.sym_tbl[i].st_bind = self.to_st_bind(self.sym_tbl[i].st_info);

            // st_other
            reader.read_exact(&mut c)?;
            self.sym_tbl[i].st_other = u8::from_le_bytes(c);

            // st_shndx
            let mut half_word = [0; 2];
            reader.read_exact(&mut half_word)?;
            self.sym_tbl[i].st_shndx = u16::from_le_bytes(half_word);

            // st_value
            let mut word64 = [0; 8];
            reader.read_exact(&mut word64)?;
            self.sym_tbl[i].st_value = u64::from_le_bytes(word64);

            // st_size
            reader.read_exact(&mut word64)?;
            self.sym_tbl[i].st_size = u64::from_le_bytes(word64);
        }

        Ok(())
    }

    /// strtabセクションデータリード
    fn read_strtab(&self, reader: &mut BufReader<File>) -> Result<Vec<u8>> {
        // .strtabセクションをサーチ(shstrtabは除外する)
        let strtab = match
            self.sec_header
                .iter()
                .filter(|s| self.to_shtype(s.sh_type) == ShType::StrTab && s.sh_no != self.header.e_shstrndx)
                .collect::<Vec<&ElfSecHeader>>()
                .pop() {
            Some(header) => header,
            _ => return Err(Error::new(ErrorKind::NotFound, "Not found strtab"))
        };

        // strtab情報をリード
        reader.seek(SeekFrom::Start(strtab.sh_offset))?;
        let mut buf: Vec<u8> = vec![0; strtab.sh_size as usize];
        reader.read_exact(&mut buf)?;

        Ok(buf)
    }

    /// strtabセクションデータリード（for section name）
    fn read_strtab_of_sec(&self, reader: &mut BufReader<File>) -> Result<Vec<u8>> {
        // .strtabセクションをサーチ(shstrtab)
        let strtab = match
            self.sec_header
                .iter()
                .filter(|s| self.to_shtype(s.sh_type) == ShType::StrTab && s.sh_no == self.header.e_shstrndx)
                .collect::<Vec<&ElfSecHeader>>()
                .pop() {
            Some(header) => header,
            _ => return Err(Error::new(ErrorKind::NotFound, "Not found strtab"))
        };

        // strtab情報をリード
        reader.seek(SeekFrom::Start(strtab.sh_offset))?;
        let mut buf: Vec<u8> = vec![0; strtab.sh_size as usize];
        reader.read_exact(&mut buf)?;

        Ok(buf)
    }

    /// SH_TYPE変換
    fn to_shtype(&self, t: Elf64Word) -> ShType {
        match t {
            0  => ShType::Null,
            1  => ShType::Progbit,
            2  => ShType::ShmTab,
            3  => ShType::StrTab,
            4  => ShType::Rela,
            5  => ShType::Hash,
            6  => ShType::Dynamic,
            7  => ShType::Note,
            8  => ShType::Nobits,
            9  => ShType::Rel,
            10 => ShType::Shlib,
            11 => ShType::DynSym,
            0x7000_0000 => ShType::LoProc,
            0x7FFF_FFFF => ShType::HiProc,
            0x8000_0000 => ShType::LoUser,
            0x8FFF_FFFF => ShType::HiUser,
            _ => ShType::Unknown,
        }
    }

    /// StType変換
    fn to_st_type(&self, t: u8) -> StType {
        match t & MASK_ST_TYPE {
            0 => StType::Notype,
            1 => StType::Object,
            2 => StType::Func,
            _ => StType::Unknown,
        }
    }

    /// StBind変換
    fn to_st_bind(&self, t: u8) -> StBind {
        match (t & MASK_ST_BIND) >> SHIFT_ST_BIND {
            0 => StBind::Local,
            1 => StBind::Global,
            2 => StBind::Weak,
            _ => StBind::Unknown,
        }
    }

    /// Null Terminator文字列
    ///
    /// シンボルが入っているセクションデータと文字列開始位置を受け取り、
    /// NullTermnateである文字列を返却する
    fn to_string(&self, buf: &[u8], offset: usize) -> String {
        let t: Vec<u8> = buf
            .iter()
            .skip(offset)
            .take_while(|&c| *c != 0) // nullまで読み込み
            .cloned()
            .collect();
        String::from_utf8(t).unwrap()
    }
}
