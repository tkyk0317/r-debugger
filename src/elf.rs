use std::fs::File;
use std::io::{Read, BufReader, SeekFrom, Seek};
use symbolic_demangle::{ demangle };

type Elf64Half = u16;
type Elf64Word = u32;
type Elf64Addr = u64;
type Elf64Offset = u64;
type Elf64Xword = u64;

const IDENT_SIZE: usize = 16;

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
struct ElfSecHeader {
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
    no: Elf64Half, // セクション番号（管理のため追加）
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
            no: 0,
        }
    }
}

// シンボルテーブル
#[derive(Debug,Clone)]
pub struct SymTbl {
    pub st_name: Elf64Word,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: Elf64Half,
    pub st_value: Elf64Addr,
    pub st_size: Elf64Xword,
    pub name: String, // strtabから読み取ったシンボル名（管理上の為、追加）
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
            name: "".to_string(),
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
        }
    }

    /// ELFデータロード
    pub fn load(&mut self) {
        // ELFヘッダーロード
        let mut reader = BufReader::new(File::open(&self.path).expect("not found file"));
        self.load_elf_header(&mut reader);

        // プログラムヘッダーロード
        self.load_prog_header(&mut reader);

        // セクションヘッダーロード
        self.load_sec_header(&mut reader);

        // シンボルテーブルロード
        self.load_symtab(&mut reader);
    }

    /// シンボルサーチ
    pub fn search_sym(&self, sym_name: &str) -> Option<&SymTbl> {
        self.sym_tbl.iter().find(|sym| *sym_name == demangle(&sym.name))
    }

    /// ELFヘッダー読み込み
    fn load_elf_header(&mut self, reader: &mut BufReader<File>) {
        // e_ident
        reader.read_exact(&mut self.header.e_ident).expect("cannot read elf data");

        // e_type
        let mut half_word = [0; 2];
        reader.read_exact(&mut half_word).expect("cannot read elf data");
        self.header.e_type = u16::from_le_bytes(half_word);

        // e_machine
        reader.read_exact(&mut half_word).expect("cannot read elf data");
        self.header.e_machine = u16::from_le_bytes(half_word);

        // e_version
        let mut word = [0; 4];
        reader.read_exact(&mut word).expect("cannot read elf data");
        self.header.e_version = u32::from_le_bytes(word);

        // e_entry
        let mut word64 = [0; 8];
        reader.read_exact(&mut word64).expect("cannot read elf data");
        self.header.e_entry = u64::from_le_bytes(word64);

        // e_phoff
        reader.read_exact(&mut word64).expect("cannot read elf data");
        self.header.e_phoff = u64::from_le_bytes(word64);

        // e_shoff
        reader.read_exact(&mut word64).expect("cannot read elf data");
        self.header.e_shoff = u64::from_le_bytes(word64);

        // e_flags
        reader.read_exact(&mut word).expect("cannot read elf data");
        self.header.e_flags = u32::from_le_bytes(word);

        // e_ehsize
        reader.read_exact(&mut half_word).expect("cannot read elf data");
        self.header.e_ehsize = u16::from_le_bytes(half_word);

        // e_phentsize
        reader.read_exact(&mut half_word).expect("cannot read elf data");
        self.header.e_phentsize = u16::from_le_bytes(half_word);

        // e_phnum
        reader.read_exact(&mut half_word).expect("cannot read elf data");
        self.header.e_phnum = u16::from_le_bytes(half_word);

        // e_shentsize
        reader.read_exact(&mut half_word).expect("cannot read elf data");
        self.header.e_shentsize = u16::from_le_bytes(half_word);

        // e_shnum
        reader.read_exact(&mut half_word).expect("cannot read elf data");
        self.header.e_shnum = u16::from_le_bytes(half_word);

        // e_shstrndx
        reader.read_exact(&mut half_word).expect("cannot read elf data");
        self.header.e_shstrndx = u16::from_le_bytes(half_word);

        // プログラムヘッダー、セクションヘッダー数が判明したので、リサイズ
        self.prog_header.resize(self.header.e_phnum as usize, ElfProgHeader::new());
        self.sec_header.resize(self.header.e_shnum as usize, ElfSecHeader::new());
    }

    /// プログラムヘッダーロード
    fn load_prog_header(&mut self, reader: &mut BufReader<File>) {
        // プログラムヘッダー位置へSeek
        reader.seek(SeekFrom::Start(self.header.e_phoff)).expect("[load_prog_header] seek error");

        for i in 0..self.header.e_phnum {
            // p_type
            let mut word = [0; 4];
            reader.read_exact(&mut word).expect("cannot read prog sec header");
            self.prog_header[i as usize].p_type = u32::from_le_bytes(word);

            // p_flags
            reader.read_exact(&mut word).expect("cannot read elf prog header");
            self.prog_header[i as usize].p_flags = u32::from_le_bytes(word);

            // p_flags
            let mut word64 = [0; 8];
            reader.read_exact(&mut word64).expect("cannot read elf prog header");
            self.prog_header[i as usize].p_offset = u64::from_le_bytes(word64);

            // p_vaddr
            reader.read_exact(&mut word64).expect("cannot read elf prog header");
            self.prog_header[i as usize].p_vaddr = u64::from_le_bytes(word64);

            // p_paddr
            reader.read_exact(&mut word64).expect("cannot read elf prog header");
            self.prog_header[i as usize].p_paddr = u64::from_le_bytes(word64);

            // p_memsz
            reader.read_exact(&mut word64).expect("cannot read elf prog header");
            self.prog_header[i as usize].p_memsz = u64::from_le_bytes(word64);

            // p_align
            reader.read_exact(&mut word64).expect("cannot read elf prog header");
            self.prog_header[i as usize].p_align = u64::from_le_bytes(word64);
        }
    }

    /// セクションヘッダーロード
    fn load_sec_header(&mut self, reader: &mut BufReader<File>) {
        // セクションヘッダー位置へSeek
        reader.seek(SeekFrom::Start(self.header.e_shoff)).expect("[load_sec_header] seek error");

        for i in 0..self.header.e_shnum {
            // sh_name
            let mut word = [0; 4];
            reader.read_exact(&mut word).expect("cannot read elf sec header");
            self.sec_header[i as usize].sh_name = u32::from_le_bytes(word);

            // sh_type
            reader.read_exact(&mut word).expect("cannot read elf sec header");
            self.sec_header[i as usize].sh_type = u32::from_le_bytes(word);

            // sh_flags
            let mut word64 = [0; 8];
            reader.read_exact(&mut word64).expect("cannot read elf sec header");
            self.sec_header[i as usize].sh_flags = u64::from_le_bytes(word64);

            // sh_addr
            reader.read_exact(&mut word64).expect("cannot read elf sec header");
            self.sec_header[i as usize].sh_addr = u64::from_le_bytes(word64);

            // sh_offset
            reader.read_exact(&mut word64).expect("cannot read elf sec header");
            self.sec_header[i as usize].sh_offset = u64::from_le_bytes(word64);

            // sh_size
            reader.read_exact(&mut word64).expect("cannot read elf sec header");
            self.sec_header[i as usize].sh_size = u64::from_le_bytes(word64);

            // sh_link
            reader.read_exact(&mut word).expect("cannot read elf sec header");
            self.sec_header[i as usize].sh_link = u32::from_le_bytes(word);

            // sh_info
            reader.read_exact(&mut word).expect("cannot read elf sec header");
            self.sec_header[i as usize].sh_info = u32::from_le_bytes(word);

            // sh_addralign
            reader.read_exact(&mut word64).expect("cannot read elf sec header");
            self.sec_header[i as usize].sh_addralign= u64::from_le_bytes(word64);

            // sh_entsize
            reader.read_exact(&mut word64).expect("cannot read elf sec header");
            self.sec_header[i as usize].sh_entsize = u64::from_le_bytes(word64);

            // セクション番号としてインデックスを設定
            // ※ セクション番号はセクションの並び順序と等しい
            self.sec_header[i as usize].no = i;
        }
    }

    /// シンボルテーブルロード
    fn load_symtab(&mut self, reader: &mut BufReader<File>) {
        // strtab情報をリード(Seekされているので注意)
        let strtab_buf = self.read_strtab(reader);

        // symtab位置までSeek
        let symtab = match
            self.sec_header
                .iter()
                .filter(|s| self.to_shtype(s.sh_type) == ShType::ShmTab)
                .collect::<Vec<&ElfSecHeader>>()
                .pop() {
            Some(header) => header,
            _ => panic!("[load_symtab] not found shmtab section")
        };
        reader.seek(SeekFrom::Start(symtab.sh_offset)).expect("[load_symtab] seek error");

        // sym_tblリサイズ
        let count = (symtab.sh_size / symtab.sh_entsize) as usize;
        self.sym_tbl.resize(count, SymTbl::new());

        // すべてのシンボルをロード
        for i in 0..count {
            // st_name
            let mut word = [0; 4];
            reader.read_exact(&mut word).expect("cannot read symtbl");
            let offset = u32::from_le_bytes(word);
            self.sym_tbl[i].st_name = offset;

            // 実際のシンボル名をstrtabセクションからリード
            self.sym_tbl[i].name = self.to_string(&strtab_buf, offset as usize);

            // st_info
            let mut c = [0; 1];
            reader.read_exact(&mut c).expect("cannot read symtbl");
            self.sym_tbl[i].st_info = u8::from_le_bytes(c);

            // st_other
            reader.read_exact(&mut c).expect("cannot read symtbl");
            self.sym_tbl[i].st_other = u8::from_le_bytes(c);

            // st_shndx
            let mut half_word = [0; 2];
            reader.read_exact(&mut half_word).expect("cannot read symtbl");
            self.sym_tbl[i].st_shndx = u16::from_le_bytes(half_word);

            // st_value
            let mut word64 = [0; 8];
            reader.read_exact(&mut word64).expect("cannot read symtbl");
            self.sym_tbl[i].st_value = u64::from_le_bytes(word64);

            // st_size
            reader.read_exact(&mut word64).expect("cannot read symtbl");
            self.sym_tbl[i].st_size = u64::from_le_bytes(word64);
        }
    }

    /// strtabセクションデータリード
    fn read_strtab(&self, reader: &mut BufReader<File>) -> Vec<u8> {
        // .strtabセクションをサーチ(shstrtabは除外する)
        let strtab = match
            self.sec_header
                .iter()
                .filter(|s| self.to_shtype(s.sh_type) == ShType::StrTab && s.no != self.header.e_shstrndx)
                .collect::<Vec<&ElfSecHeader>>()
                .pop() {
            Some(header) => header,
            _ => panic!("[read_strtab] not found strtab section")
        };

        // strtab情報をリード
        reader.seek(SeekFrom::Start(strtab.sh_offset)).expect("[read_strtab] seek error");
        let mut buf: Vec<u8> = vec![0; strtab.sh_size as usize];
        reader.read_exact(&mut buf).expect("cannot read strtab");

        buf
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
