use std::fs::File;
use std::io::{Read, BufReader, Seek, SeekFrom, Result, Error, ErrorKind};

use crate::elf::elf64::ElfSecHeader;
use crate::elf::leb128::ULEB128;

/// DW_TAG情報
#[derive(Debug,PartialEq)]
enum DwTagInfo {
    Unknown, // 不明
    ArrayType,
    ClassType,
    EntryPoint,
    EnumerationType,
    FormalParamter,
    ImportedDeclaration,
    Label,
    LexicalBlock,
    Member,
    PointerType,
    ReferenceType,
    CompileUnit,
    StringType,
    StructureType,
    SubroutineType,
    Typedef,
    UnionType,
    UnspecifiedParameters,
    Variant,
    CommonBlock,
    CommonInclusion,
    Inheritance,
    InlinedSubroutine,
    Module,
    PtrToMemberType,
    SetType,
    SubrangeType,
    WithStmt,
    AccessDeclaration,
    BaseType,
    CatchBlock,
    ConstType,
    Constant,
    Enumerator,
    FileType,
    Friend,
    Namelist,
    NamelistItem,
    PackedType,
    Subprogram,
    TemplateTypeParameter,
    TemplateValueParameter,
    ThrownType,
    TryBlock,
    VariantPart,
    Variable,
    VolatileType,
    // DWARF 3 values
    DwarfProceduer,
    RestritctType,
    InterfaceType,
    Namespace,
    ImportedModule,
    UnspecifiedType,
    PartialUnit,
    ImportedUnit,
    Condition,
    SharedType,
    // DWARF 4 values
    TypeUnit,
    RvalueReferenceType,
    TemplateAlias,
    LoUser,
    HiUser,
}

/// DW_AT情報
#[derive(Debug,Clone,PartialEq)]
enum DwAtInfo {
    Unknown, // 不明
    Sibling,
    Location,
    Name,
    Ordering,
    SubscrData,
    ByteSize,
    BitOffset,
    BitSize,
    ElementList,
    StmtList,
    LowPc,
    HighPc,
    Language,
    Member,
    Discr,
    DiscrValue,
    Visibility,
    Import,
    StringLength,
    CommonReference,
    CompDir,
    ConstValue,
    ContainingType,
    DefaultValue,
    Inline,
    IsOptional,
    LowerBound,
    Producer,
    Prototyped,
    ReturnAddr,
    StartScope,
    BitStride,
    UpperBound,
    AbstractOrigin,
    Accessibility,
    AddressClass,
    Artificial,
    BaseTypes,
    CallingConvention,
    Count,
    DataMemberLocation,
    DeclColumn,
    DeclFile,
    DeclLine,
    Declaration,
    DiscrList,
    Encoding,
    External,
    FrameBase,
    Friend,
    IdentifierCase,
    MacroInfo,
    NamelistItems,
    Priority,
    Segment,
    Specification,
    StaticLink,
    Type,
    UseLocation,
    VariableParameter,
    Virtuality,
    VtableElemLocation,
    // DWARF 3 values
    Allocated,
    Associated,
    DataLocation,
    ByteStride,
    EntryPc,
    UseUTF8,
    Extension,
    Ranges,
    Trampoline,
    CallColumn,
    CallFile,
    CallLine,
    Description,
    BinaryScale,
    DecimalScale,
    Small,
    DecimalSign,
    DigitCount,
    PictureString,
    Mutable,
    ThreadsScaled,
    Explicit,
    ObjectPointer,
    Endianity,
    Elemental,
    Pure,
    Recursive,
    // DWARF 4 values
    Signature,
    MainSubprogram,
    DataBitOffset,
    ConstExpr,
    EnumClass,
    LinkageName,
    End, // 終了attr
}

/// DW_FORM情報
#[derive(Debug)]
enum DwFormInfo {
    Unknown, // 不明
    Addr,
    Block2,
    Block4,
    Data2,
    Data4,
    Data8,
    String,
    Block,
    Block1,
    Data1,
    Flag,
    Sdata,
    Strp,
    Udata,
    RefAddr,
    Ref1,
    Ref2,
    Ref4,
    Ref8,
    RefUdata,
    Indirect,
    // dwarf4
    SecOffset,
    Exprloc,
    FlagPresent,
    RefSig8,
    End, // 終了form
}

/// DW情報変換trait
trait DwInfo {
    /// DW_TAGコンバート
    fn to_dw_tag(tag: u64) -> DwTagInfo {
        match tag {
            0x1  => DwTagInfo::ArrayType,
            0x2  => DwTagInfo::ClassType,
            0x3  => DwTagInfo::EntryPoint,
            0x4  => DwTagInfo::EnumerationType,
            0x5  => DwTagInfo::FormalParamter,
            0x8  => DwTagInfo::ImportedDeclaration,
            0xA  => DwTagInfo::Label,
            0xB  => DwTagInfo::LexicalBlock,
            0xD  => DwTagInfo::Member,
            0xF  => DwTagInfo::PointerType,
            0x10 => DwTagInfo::ReferenceType,
            0x11 => DwTagInfo::CompileUnit,
            0x12 => DwTagInfo::StringType,
            0x13 => DwTagInfo::StructureType,
            0x15 => DwTagInfo::SubroutineType,
            0x16 => DwTagInfo::Typedef,
            0x17 => DwTagInfo::UnionType,
            0x18 => DwTagInfo::UnspecifiedParameters,
            0x19 => DwTagInfo::Variant,
            0x1A => DwTagInfo::CommonBlock,
            0x1B => DwTagInfo::CommonInclusion,
            0x1C => DwTagInfo::Inheritance,
            0x1D => DwTagInfo::InlinedSubroutine,
            0x1E => DwTagInfo::Module,
            0x1F => DwTagInfo::PtrToMemberType,
            0x20 => DwTagInfo::SetType,
            0x21 => DwTagInfo::SubrangeType,
            0x22 => DwTagInfo::WithStmt,
            0x23 => DwTagInfo::AccessDeclaration,
            0x24 => DwTagInfo::BaseType,
            0x25 => DwTagInfo::CatchBlock,
            0x26 => DwTagInfo::ConstType,
            0x27 => DwTagInfo::Constant,
            0x28 => DwTagInfo::Enumerator,
            0x29 => DwTagInfo::FileType,
            0x2A => DwTagInfo::Friend,
            0x2B => DwTagInfo::Namelist,
            0x2C => DwTagInfo::NamelistItem,
            0x2D => DwTagInfo::PackedType,
            0x2E => DwTagInfo::Subprogram,
            0x2F => DwTagInfo::TemplateTypeParameter,
            0x30 => DwTagInfo::TemplateValueParameter,
            0x31 => DwTagInfo::ThrownType,
            0x32 => DwTagInfo::TryBlock,
            0x33 => DwTagInfo::VariantPart,
            0x34 => DwTagInfo::Variable,
            0x35 => DwTagInfo::VolatileType,
            0x36 => DwTagInfo::DwarfProceduer,
            0x37 => DwTagInfo::RestritctType,
            0x38 => DwTagInfo::InterfaceType,
            0x39 => DwTagInfo::Namespace,
            0x3A => DwTagInfo::ImportedModule,
            0x3B => DwTagInfo::UnspecifiedType,
            0x3C => DwTagInfo::PartialUnit,
            0x3D => DwTagInfo::ImportedUnit,
            0x3F => DwTagInfo::Condition,
            0x40 => DwTagInfo::SharedType,
            0x41 => DwTagInfo::TypeUnit,
            0x42 => DwTagInfo::RvalueReferenceType,
            0x43 => DwTagInfo::TemplateAlias,
            0x4080 => DwTagInfo::LoUser,
            0xFFFF => DwTagInfo::HiUser,
            _ =>  DwTagInfo::Unknown,
        }
    }

    /// has childコンバート
    fn to_has_child(c: u8) -> &'static str {
        match c {
            1 => "has children",
            _ => "no children"
        }
    }

    /// DW_ATコンバート
    fn to_dw_at(at: u64) -> DwAtInfo {
        match at {
            0x0  => DwAtInfo::End,
            0x1  => DwAtInfo::Sibling,
            0x2  => DwAtInfo::Location,
            0x3  => DwAtInfo::Name,
            0x9  => DwAtInfo::Ordering,
            0xA => DwAtInfo::SubscrData,
            0xB => DwAtInfo::ByteSize,
            0xC => DwAtInfo::BitOffset,
            0xD => DwAtInfo::BitSize,
            0xF => DwAtInfo::ElementList,
            0x10 => DwAtInfo::StmtList,
            0x11 => DwAtInfo::LowPc,
            0x12 => DwAtInfo::HighPc,
            0x13 => DwAtInfo::Language,
            0x14 => DwAtInfo::Member,
            0x15 => DwAtInfo::Discr,
            0x16 => DwAtInfo::DiscrValue,
            0x17 => DwAtInfo::Visibility,
            0x18 => DwAtInfo::Import,
            0x19 => DwAtInfo::StringLength,
            0x1A => DwAtInfo::CommonReference,
            0x1B => DwAtInfo::CompDir,
            0x1C => DwAtInfo::ConstValue,
            0x1D => DwAtInfo::ContainingType,
            0x1E => DwAtInfo::DefaultValue,
            0x20 => DwAtInfo::Inline,
            0x21 => DwAtInfo::IsOptional,
            0x22 => DwAtInfo::LowerBound,
            0x25 => DwAtInfo::Producer,
            0x27 => DwAtInfo::Prototyped,
            0x2A => DwAtInfo::ReturnAddr,
            0x2C => DwAtInfo::StartScope,
            0x2E => DwAtInfo::BitStride,
            0x2F => DwAtInfo::UpperBound,
            0x31 => DwAtInfo::AbstractOrigin,
            0x32 => DwAtInfo::Accessibility,
            0x33 => DwAtInfo::AddressClass,
            0x34 => DwAtInfo::Artificial,
            0x35 => DwAtInfo::BaseTypes,
            0x36 => DwAtInfo::CallingConvention,
            0x37 => DwAtInfo::Count,
            0x38 => DwAtInfo::DataMemberLocation,
            0x39 => DwAtInfo::DeclColumn,
            0x3A => DwAtInfo::DeclFile,
            0x3B => DwAtInfo::DeclLine,
            0x3C => DwAtInfo::Declaration,
            0x3D => DwAtInfo::DiscrList,
            0x3E => DwAtInfo::Encoding,
            0x3F => DwAtInfo::External,
            0x40 => DwAtInfo::FrameBase,
            0x41 => DwAtInfo::Friend,
            0x42 => DwAtInfo::IdentifierCase,
            0x43 => DwAtInfo::MacroInfo,
            0x44 => DwAtInfo::NamelistItems,
            0x45 => DwAtInfo::Priority,
            0x46 => DwAtInfo::Segment,
            0x47 => DwAtInfo::Specification,
            0x48 => DwAtInfo::StaticLink,
            0x49 => DwAtInfo::Type,
            0x4A => DwAtInfo::UseLocation,
            0x4B => DwAtInfo::VariableParameter,
            0x4C => DwAtInfo::Virtuality,
            0x4D => DwAtInfo::VtableElemLocation,
            0x4E => DwAtInfo::Allocated,
            0x4F => DwAtInfo::Associated,
            0x50 => DwAtInfo::DataLocation,
            0x51 => DwAtInfo::ByteStride,
            0x52 => DwAtInfo::EntryPc,
            0x53 => DwAtInfo::UseUTF8,
            0x54 => DwAtInfo::Extension,
            0x55 => DwAtInfo::Ranges,
            0x56 => DwAtInfo::Trampoline,
            0x57 => DwAtInfo::CallColumn,
            0x58 => DwAtInfo::CallFile,
            0x59 => DwAtInfo::CallLine,
            0x5A => DwAtInfo::Description,
            0x5B => DwAtInfo::BinaryScale,
            0x5C => DwAtInfo::DecimalScale,
            0x5D => DwAtInfo::Small,
            0x5E => DwAtInfo::DecimalSign,
            0x5F => DwAtInfo::DigitCount,
            0x60 => DwAtInfo::PictureString,
            0x61 => DwAtInfo::Mutable,
            0x62 => DwAtInfo::ThreadsScaled,
            0x63 => DwAtInfo::Explicit,
            0x64 => DwAtInfo::ObjectPointer,
            0x65 => DwAtInfo::Endianity,
            0x66 => DwAtInfo::Elemental,
            0x67 => DwAtInfo::Pure,
            0x68 => DwAtInfo::Recursive,
            0x69 => DwAtInfo::Signature,
            0x6A => DwAtInfo::MainSubprogram,
            0x6B => DwAtInfo::DataBitOffset,
            0x6C => DwAtInfo::ConstExpr,
            0x6D => DwAtInfo::EnumClass,
            0x6E => DwAtInfo::LinkageName,
            _ =>  DwAtInfo::Unknown,
        }
    }

    /// DW_FROMコンバート
    fn to_dw_form(form: u64) -> DwFormInfo {
        match form {
            0x0  => DwFormInfo::End,
            0x1  => DwFormInfo::Addr,
            0x3  => DwFormInfo::Block2,
            0x4  => DwFormInfo::Block4,
            0x5  => DwFormInfo::Data2,
            0x6  => DwFormInfo::Data4,
            0x7  => DwFormInfo::Data8,
            0x8 => DwFormInfo::String,
            0x9 => DwFormInfo::Block,
            0xA => DwFormInfo::Block1,
            0xB => DwFormInfo::Data1,
            0xC => DwFormInfo::Flag,
            0xD => DwFormInfo::Sdata,
            0xE  => DwFormInfo::Strp,
            0xF => DwFormInfo::Udata,
            0x10 => DwFormInfo::RefAddr,
            0x11 => DwFormInfo::Ref1,
            0x12 => DwFormInfo::Ref2,
            0x13 => DwFormInfo::Ref4,
            0x14 => DwFormInfo::Ref8,
            0x15 => DwFormInfo::RefUdata,
            0x16 => DwFormInfo::Indirect,
            0x17 => DwFormInfo::SecOffset,
            0x18 => DwFormInfo::Exprloc,
            0x19 => DwFormInfo::FlagPresent,
            0x20 => DwFormInfo::RefSig8,
            _ =>  DwFormInfo::Unknown,
        }
    }
}

/// abbrev record
#[derive(Debug)]
struct DebugAbbRevRecord {
    abbrev_no: u64,      // 実際は、ULEB128
    tag: u64,            // 実際は、ULEB128
    has_child: u8,       // このDIRをもつかどうか
    attr_name: Vec<u64>, // 実際は、ULEB128の配列
    attr_form: Vec<u64>, // 実際は、ULEB128の配列
}
impl DwInfo for DebugAbbRevRecord {}
impl DebugAbbRevRecord {
    /// コンストラクタ
    fn new() -> Self {
        DebugAbbRevRecord {
            abbrev_no: 0,
            tag: 0,
            has_child: 0,
            attr_name: vec![],
            attr_form: vec![]
        }
    }

    /// abbrev情報表示
    fn show(&self) {
        println!(
            "{} {:?} [child: {}]",
            self.abbrev_no,
            Self::to_dw_tag(self.tag),
            Self::to_has_child(self.has_child)
        );
        for (n, f) in self.attr_name.iter().zip(self.attr_form.iter()) {
            println!("    {:?} {:?}", Self::to_dw_at(*n), Self::to_dw_form(*f));
        }
    }

}

/// abbrev section
#[derive(Debug)]
struct DebugAbbRevSection {
    abb_rev: Vec<DebugAbbRevRecord>
}

impl ULEB128 for DebugAbbRevSection {}
impl DebugAbbRevSection {
    /// コンストラクタ
    pub fn new() -> Self {
        DebugAbbRevSection {
            abb_rev: vec![]
        }
    }

    /// abbrev record取得
    pub fn get_record(&self, i: usize) -> &DebugAbbRevRecord { &self.abb_rev[i] }

    /// AbbRevセクションロード
    pub fn load(
        &mut self, reader: &mut BufReader<File>, sec_header: &ElfSecHeader, abbrev_offset: u64
    ) -> Result<()> {
        // debug_abbrevセクションへ移動
        let offset = sec_header.get_offset() + abbrev_offset;
        reader.seek(SeekFrom::Start(offset))?;

        // 各データをロード
        loop {
            let mut abbrev = DebugAbbRevRecord::new();
            abbrev.abbrev_no = Self::decode(reader).unwrap().1;

            // noがゼロならば、abbrevは終了
            if 0 == abbrev.abbrev_no {
                break;
            }
            abbrev.tag = Self::decode(reader).unwrap().1;

            // has_childは1byte
            let mut b = [0; 1];
            reader.read_exact(&mut b)?;
            abbrev.has_child = u8::from_le_bytes(b);

            // attribute/formコードをロード（name=0x00, form=0x00までループ)
            loop {
                let attr_name = Self::decode(reader).unwrap().1;
                let attr_form = Self::decode(reader).unwrap().1;
                abbrev.attr_name.push(attr_name);
                abbrev.attr_form.push(attr_form);

                // attr/formが共にゼロであれば、終了
                if 0 == attr_name && 0 == attr_form {
                    break;
                }
            }

            // abbrevデータ保存
            self.abb_rev.push(abbrev);
        }

        Ok(())
    }

    /// abbrev表示
    #[allow(dead_code)]
    fn show(&self) {
        for a in &self.abb_rev {
            a.show();
        }
    }
}

/// debug_lineセクションに存在するfile_namesデータ
#[derive(Debug)]
struct Filenames {
    name: String,
    dir_entry: u64,
    last_modify: u64,
    size: u64,
}
impl Filenames {
    /// コンストラクタ
    pub fn new() -> Self {
        Filenames {
            name: "".to_string(),
            dir_entry: 0,
            last_modify: 0,
            size: 0,
        }
    }
}

/// debug_lineセクションヘッダ情報
#[derive(Debug)]
struct DebugLineHeader {
    len: u32,
    version: u16,
    header_len: u32,
    min_inst_len: u8,
    max_ope_len: u8,
    is_stmt: u8,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
    standard_opcode_len: Vec<u64>,
    inc_dirs: Vec<String>,
    file_names: Vec<Filenames>,
}
impl DebugLineHeader {
    /// コンストラクタ
    pub fn new() -> Self {
        DebugLineHeader {
            len: 0,
            version: 0,
            header_len: 0,
            min_inst_len: 0,
            max_ope_len: 0,
            is_stmt: 0,
            line_base: 0,
            line_range: 0,
            opcode_base: 0,
            standard_opcode_len: vec![],
            inc_dirs: vec![],
            file_names: vec![]
        }
    }
}

/// debug_lineセクション
#[derive(Debug)]
struct DebugLineSection {
    offset: u64, // セクションデータ先頭へのオフセット
    cu_header: Vec<DebugLineHeader>, // CU毎に定義されているヘッダー情報
}

impl ULEB128 for DebugLineSection {}
impl DebugLineSection {
    /// コンストラクタ
    pub fn new(o: u64) -> Self {
        DebugLineSection {
            offset: o,
            cu_header: vec![],
        }
    }

    /// debug_line ロード処理
    pub fn load(&mut self, path: &str, offset: u64) -> Result<()> {
        // debug_lineセクション先頭へ移動
        let f = File::open(&path)?;
        let mut reader = BufReader::new(f);
        reader.seek(SeekFrom::Start(self.offset + offset))?;

        // headerのロード
        let h = self.load_header(&mut reader)?;
        self.cu_header.push(h);

        Ok(())
    }

    /// debug line情報表示
    pub fn show(&self) {
        println!("The line numebr program header");
        self.cu_header.iter().for_each(|h| {
            println!("    len:          {}", h.len);
            println!("    version:      {}", h.version);
            println!("    header len:   {}", h.header_len);
            println!("    min inst len: {}", h.min_inst_len);
            println!("    max ope len:  {}", h.max_ope_len);
            println!("    is stmt:      {}", h.is_stmt);
            println!("    line base:    {}", h.line_base);
            println!("    line range:   {}", h.line_range);
            println!("    opecode base: {}", h.opcode_base);
            println!();
            println!("    ope code:");
            for (i, ope) in h.standard_opcode_len.iter().enumerate() {
                println!("    opecode {}: has {} argment", i + 1, ope);
            };
            println!();
            println!("    directory entry:");
            for (i, entry) in h.inc_dirs.iter().enumerate() {
                println!("    no {}: {}", i + 1, entry);
            }
            println!();
            println!("    file entry:");
            for entry in &h.file_names {
                println!(
                    "    dir no: {} last modify: {} size: {} {}",
                    entry.dir_entry, entry.last_modify, entry.size, entry.name
                );
            }
            println!();
        });
    }

    /// headerロード
    fn load_header(&self, reader: &mut BufReader<File>) -> Result<DebugLineHeader> {
        let mut header = DebugLineHeader::new();

        // len
        let mut word = [0; 4];
        reader.read_exact(&mut word)?;
        header.len = u32::from_le_bytes(word);

        // version
        let mut half_word = [0; 2];
        reader.read_exact(&mut half_word)?;
        header.version = u16::from_le_bytes(half_word);

        // header len
        reader.read_exact(&mut word)?;
        header.header_len = u32::from_le_bytes(word);

        // min inst len
        let mut byte = [0; 1];
        reader.read_exact(&mut byte)?;
        header.min_inst_len = u8::from_le_bytes(byte);

        // max ope len
        reader.read_exact(&mut byte)?;
        header.max_ope_len = u8::from_le_bytes(byte);

        // is stmt
        reader.read_exact(&mut byte)?;
        header.max_ope_len = u8::from_le_bytes(byte);

        // line base
        reader.read_exact(&mut byte)?;
        header.line_base = i8::from_le_bytes(byte);

        // line range
        reader.read_exact(&mut byte)?;
        header.line_range = u8::from_le_bytes(byte);

        // opecode base
        reader.read_exact(&mut byte)?;
        header.opcode_base = u8::from_le_bytes(byte);

        // standard opecode len([opecode base - 1]個分)
        (0..header.opcode_base - 1).for_each(|_| {
            if let Ok(arg) = Self::decode(reader) {
                header.standard_opcode_len.push(arg.1);
            }
        });

        // include directories
        loop {
            // null終端までがディレクトリエントリー
            let s = self.get_null_term_str(reader)?;

            // 最後のエントリーはNULL文字
            if s.is_empty() { break; }

            // include directory保存
            header.inc_dirs.push(s);
        }

        // file names
        loop {
            // null終端までがファイル名
            let mut f = Filenames::new();
            let s = self.get_null_term_str(reader)?;

            // 最後のエントリーはNULL文字
            if s.is_empty() { break; }
            f.name = s;

            // directory entry
            if let Ok(entry) = Self::decode(reader) { f.dir_entry = entry.1; }

            // last modification
            if let Ok(modify) = Self::decode(reader) { f.last_modify = modify.1; }

            // file size
            if let Ok(size) = Self::decode(reader) { f.size = size.1; }

            // file name情報を保存
            header.file_names.push(f)
        }

        Ok(header)
    }

    /// null終端までの文字列を取得
    fn get_null_term_str(&self, reader: &mut BufReader<File>) -> Result<String> {
        let mut buf = vec![];
        loop {
            // null終端までのデータを取得
            let mut byte = [0; 1];
            reader.read_exact(&mut byte)?;
            let c = u8::from_le_bytes(byte);

            // nullチェック
            if c == 0 { break; }
            buf.push(c);
        }

        // 文字列に変換し、返却
        match String::from_utf8(buf) {
            Ok(s) => Ok(s),
            Err(n) => Err(Error::new(ErrorKind::Other, n))
        }
    }
}

/// DIEレコード
#[derive(Debug)]
struct DebugInfoEntry {
    no: u64,
    attr: DwAtInfo,
    form: DwFormInfo,
    data: String,
}

impl DwInfo for DebugInfoEntry {}
impl DebugInfoEntry {
    /// コンストラクタ
    pub fn new(n: u64, a: u64, f: u64, s: &str) -> Self {
        DebugInfoEntry {
            no: n,
            attr: Self::to_dw_at(a),
            form: Self::to_dw_form(f),
            data: s.to_string()
        }
    }

    /// DIE情報表示
    #[allow(dead_code)]
    pub fn show(&self) {
        println!("[{}] {:?} {:?} {}", self.no, self.attr, self.form, self.data);
    }

    /// DwAtInfo取得
    pub fn get_at_info(&self) -> DwAtInfo { self.attr.clone() }

    /// data取得
    pub fn get_data(&self) -> &str { &self.data }
}

/// debug_info header(32bit mode)
#[derive(Debug)]
struct CUHeader {
    len: u32,                  // debug_info length(for 32bit dwarf format. 0xFFFF_FFFF when 64bit dwarf mode)
    actual_len: u64,           // debug_info length(for 64bit mode)
    version: u16,              // dwarf version
    abb_rev_offset: u32,       // debug_abbrev section offset in .debug_abbrev
    address_size: u8,          // 1-byte unsigned integer representing the size in bytes of an address on the target architecture(pointer size)
    dies: Vec<DebugInfoEntry>, // CUに紐付いたDIEを保存
}

impl CUHeader {
    /// コンストラクタ
    pub fn new() -> Self {
        CUHeader {
            len: 0,
            actual_len: 0,
            version: 0,
            abb_rev_offset: 0,
            address_size: 0,
            dies: vec![]
        }
    }

    /// ヘッダー表示
    #[allow(dead_code)]
    pub fn show(&self) {
        println!(".debug_info compile unit header:");
        println!("    length      : 0x{:x}", self.len);
        println!("    version     : 0x{:x}", self.version);
        println!("    abb offset  : 0x{:x}", self.abb_rev_offset);
        println!("    address size: 0x{:x}", self.address_size);
    }

    /// DIE取得
    pub fn get_dies(&self) -> &[DebugInfoEntry] { &self.dies }
}

/// debug_infoセクション
///
/// header/dies/abbrevは、インデックスで対応付け
#[derive(Debug)]
struct DebugInfoSection {
    header: Vec<CUHeader>,
}

impl DwInfo for DebugInfoSection {}
impl ULEB128 for DebugInfoSection {}
impl DebugInfoSection {
    /// コンストラクタ
    pub fn new() -> Self {
        DebugInfoSection {
            header: vec![],
        }
    }

    /// CU Header取得
    pub fn get_header(&self) -> &[CUHeader] { &self.header }

    /// DebugInfoSection情報表示
    pub fn show(&self) {
        for h in &self.header {
            h.show();
            for die in &h.dies {
                die.show();
            }
        }
    }

    /// debug_infoセクションロード
    fn load(
        &mut self,
        reader: &mut BufReader<File>,
        info_h: &ElfSecHeader,
        abbrev_h: &ElfSecHeader,
        str_h: &ElfSecHeader
    ) -> Result<()> {
        // debug_str読み込み
        reader.seek(SeekFrom::Start(str_h.get_offset()))?;
        let mut str_buf: Vec<u8> = vec![0; str_h.get_size() as usize];
        reader.read_exact(&mut str_buf)?;

        // debug_infoセクションへ移動
        reader.seek(SeekFrom::Start(info_h.get_offset()))?;

        // CU Headerを読み込み、CUの情報をロードする
        let mut read_size = 0;
        loop {
            let mut cu_h = CUHeader::new();

            // len
            let mut word = [0; 4];
            reader.read_exact(&mut word)?;
            cu_h.len = u32::from_le_bytes(word);
            read_size += 4;

            // load actual len when 64bit mode
            if cu_h.len == 0xFFFF_FFFF { // 64bit mode
                let mut word64 = [0; 8];
                reader.read_exact(&mut word64)?;
                cu_h.actual_len = u64::from_le_bytes(word64);
                read_size += 8;
            }

            // version
            let mut half_word = [0; 2];
            reader.read_exact(&mut half_word)?;
            cu_h.version = u16::from_le_bytes(half_word);
            read_size += 2;

            // abb_rev offset
            reader.read_exact(&mut word)?;
            cu_h.abb_rev_offset = u32::from_le_bytes(word);
            read_size += 4;

            // address size
            let mut byte = [0; 1];
            reader.read_exact(&mut byte)?;
            cu_h.address_size = u8::from_le_bytes(byte);
            read_size += 1;

            // 対応するabbrevをロード
            let mut abbrev = DebugAbbRevSection::new();
            let offset = cu_h.abb_rev_offset;
            abbrev.load(reader, &abbrev_h, offset as u64)?;

            // abbrevを読み取りながら、debug_infoセクションをロードしていく
            reader.seek(SeekFrom::Start(info_h.get_offset() + read_size))?;
            let die_size = self.parse(reader, &mut cu_h, &abbrev, &str_buf);
            read_size += die_size;

            // headerと対応するabbrevを保存
            self.header.push(cu_h);

            // debug_infoセクションすべてを読み込めば終了
            if read_size == info_h.get_size() {
                break;
            }
        }

        Ok(())
    }

    /// debug_infoセクションパーズ
    ///
    /// parseした結果とリードしたサイズを返却する
    fn parse(
        &mut self,
        reader: &mut BufReader<File>,
        cu_h: &mut CUHeader,
        abbrev: &DebugAbbRevSection,
        str_buf: &[u8]
    ) -> u64 {
        // DIEをロード
        let mut read_size = 0; // lenを除いたヘッダサイズが初期値
        loop {
            // debug_infoセクションから対応するabbrev noを読み込む
            let (size, abbrev_no) = Self::decode(reader).unwrap();
            read_size += size;

            // すべてのDIEを読み込めば終了
            let end = (read_size + 7) as u32;
            if cu_h.len == end { break; }

            // abbrev_no=ゼロならば、nullエントリーなので次のエントリーへ
            if 0 == abbrev_no {
                continue;
            }

            // noから配列インデックスへ(ELFには1オリジンで格納)
            let index = abbrev_no - 1;
            let record = abbrev.get_record(index as usize);

            // DW_FORMに応じたデータを読み取る
            for (form, at) in record.attr_form.iter().zip(record.attr_name.iter()) {
                let data = match Self::to_dw_form(*form) {
                    DwFormInfo::Strp => {
                        // DIEにはdebug_strのオフセットが入っている
                        let mut buf = [0; 4];
                        let offset = match reader.read_exact(&mut buf) {
                            Ok(_) => u32::from_le_bytes(buf),
                            Err(e) => panic!("[DebugInfoSection::parse] cannot read from debug_str {:?}", e)
                        };
                        read_size += 4;

                        // debug_strbufセクションから対応する文字列を読み込む
                        self.to_string(str_buf, offset as usize)
                    }
                    DwFormInfo::Addr => {
                        // debug_infoセクションに即値が格納
                        let mut buf = [0; 8];
                        let addr = match reader.read_exact(&mut buf) {
                            Ok(_) => u64::from_le_bytes(buf),
                            Err(e) => panic!("[DebugInfoSection::parse] cannot read from debug_info {:?}", e)
                        };
                        read_size += 8;
                        addr.to_string()
                    }
                    DwFormInfo::Data1 => {
                        // 1byteデータがdebug_infoセクションに格納
                        let mut buf = [0; 1];
                        let data = match reader.read_exact(&mut buf) {
                            Ok(_) => u8::from_le_bytes(buf),
                            Err(e) => panic!("[DebugInfoSection::parse] cannot read from debug_info {:?}", e)
                        };
                        read_size += 1;
                        data.to_string()
                    }
                    DwFormInfo::Data2 => {
                        // 2byteデータがdebug_infoセクションに格納
                        let mut buf = [0; 2];
                        let data = match reader.read_exact(&mut buf) {
                            Ok(_) => u16::from_le_bytes(buf),
                            Err(e) => panic!("[DebugInfoSection::parse] cannot read from debug_info {:?}", e)
                        };
                        read_size += 2;
                        data.to_string()
                    }
                    DwFormInfo::Data4 => {
                        // 4byteデータがdebug_infoセクションに格納
                        let mut buf = [0; 4];
                        let data = match reader.read_exact(&mut buf) {
                            Ok(_) => u32::from_le_bytes(buf),
                            Err(e) => panic!("[DebugInfoSection::parse] cannot read from debug_info {:?}", e)
                        };
                        read_size += 4;
                        data.to_string()
                    }
                    DwFormInfo::Data8 => {
                        // 8byteデータがdebug_infoセクションに格納
                        let mut buf = [0; 8];
                        let data = match reader.read_exact(&mut buf) {
                            Ok(_) => u64::from_le_bytes(buf),
                            Err(e) => panic!("[DebugInfoSection::parse] cannot read from debug_info {:?}", e)
                        };
                        read_size += 8;
                        data.to_string()
                    }
                    DwFormInfo::SecOffset => {
                        // 4byteデータがdebug_infoセクションに格納
                        let mut buf = [0; 4];
                        let data = match reader.read_exact(&mut buf) {
                            Ok(_) => u32::from_le_bytes(buf),
                            Err(e) => panic!("[DebugInfoSection::parse] cannot read from debug_info {:?}", e)
                        };
                        read_size += 4;
                        data.to_string()
                    }
                    DwFormInfo::Ref1 => {
                        // CUヘッダーからのオフセットが、.debug_infoセクションに格納
                        let mut buf = [0; 1];
                        let data = match reader.read_exact(&mut buf) {
                            Ok(_) => u8::from_le_bytes(buf),
                            Err(e) => panic!("[DebugInfoSection::parse] cannot read from debug_info {:?}", e)
                        };
                        read_size += 1;
                        data.to_string()
                    }
                    DwFormInfo::Ref2 => {
                        // CUヘッダーからのオフセットが、.debug_infoセクションに格納
                        let mut buf = [0; 2];
                        let data = match reader.read_exact(&mut buf) {
                            Ok(_) => u16::from_le_bytes(buf),
                            Err(e) => panic!("[DebugInfoSection::parse] cannot read from debug_info {:?}", e)
                        };
                        read_size += 2;
                        data.to_string()
                    }
                    DwFormInfo::Ref4 => {
                        // CUヘッダーからのオフセットが、.debug_infoセクションに格納
                        let mut buf = [0; 4];
                        let data = match reader.read_exact(&mut buf) {
                            Ok(_) => u32::from_le_bytes(buf),
                            Err(e) => panic!("[DebugInfoSection::parse] cannot read from debug_info {:?}", e)
                        };
                        read_size += 4;
                        data.to_string()
                    }
                    DwFormInfo::Ref8 => {
                        // CUヘッダーからのオフセットが、.debug_infoセクションに格納
                        let mut buf = [0; 8];
                        let data = match reader.read_exact(&mut buf) {
                            Ok(_) => u64::from_le_bytes(buf),
                            Err(e) => panic!("[DebugInfoSection::parse] cannot read from debug_info {:?}", e)
                        };
                        read_size += 8;
                        data.to_string()
                    }
                    DwFormInfo::Sdata => {
                        // sUEB128方式でdebug_infoセクションに格納
                        let (size, data) = Self::decode(reader).unwrap();
                        read_size += size;
                        data.to_string()
                    }
                    DwFormInfo::Udata => {
                        // uUEB128方式でdebug_infoセクションに格納
                        let (size, data) = Self::decode(reader).unwrap();
                        read_size += size;
                        data.to_string()
                    }
                    DwFormInfo::String => {
                        // null terminateの文字列がdebug_infoセクションに格納
                        let mut st: Vec<u8> = vec![];
                        let mut st_size = 0;
                        loop {
                             let mut buf = [0; 1];
                             let data = match reader.read_exact(&mut buf) {
                                 Ok(_) => u8::from_le_bytes(buf),
                                 Err(e) => panic!("[DebugInfoSection::parse] cannot read from debug_info {:?}", e)
                             };
                             st.push(data);
                             st_size += 1;
                             if data == 0 { break; }
                        }
                        read_size += st_size;
                        String::from_utf8(st).unwrap()
                    }
                    DwFormInfo::Exprloc => {
                        // uUEB128方式でdebug_infoセクションに格納
                        let (size, data) = Self::decode(reader).unwrap();

                        // この後に、exprlocで指定されたバイト数を読み込む
                        let mut buf = vec![0; data as usize];
                        match reader.read_exact(&mut buf) {
                            Ok(_) => {
                                // exprlocとそのデータサイズ分を加算
                                read_size += size + data;
                             }
                            Err(e) => panic!("[DebugInfoSection::parse] cannot exprloc {:?}", e)
                        }
                        data.to_string()
                    }
                    DwFormInfo::FlagPresent => {
                        // フラグが存在していることを暗黙的に示している
                        "flag is presetn".to_string()
                    }
                    DwFormInfo::End => {
                        "value: 0".to_string()
                    }
                    _ => {
                        panic!("\tnot support DW Form")
                    }
                };
                // DIEを生成し、保存
                let die = DebugInfoEntry::new(abbrev_no, *at, *form, &data);
                cu_h.dies.push(die);
            }
        }
        read_size
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

/// Dwarf情報
pub struct Dwarf {
    debug_info: DebugInfoSection,
    debug_line: Vec<DebugLineSection>,
}

impl ULEB128 for Dwarf {}
impl Dwarf {
    /// コンストラクタ
    pub fn new() -> Self {
        Dwarf {
            debug_info: DebugInfoSection::new(),
            debug_line: vec![],
        }
    }

    /// debug情報表示
    pub fn show(&self) {
        self.debug_info.show();
        self.debug_line.iter().for_each(|d| d.show());
    }

    /// debug_infoロード
    pub fn load(&mut self, path: &str, header: &[ElfSecHeader]) -> Result<()> {
        // debug_info/debug_abbrevセクションを探す
        let debug_info_sec = match self.search_debug_info_sec(&header) {
            Some(h) => h,
            _ => return Err(Error::new(ErrorKind::NotFound, "Not found debug_info section header"))
        };
        let abbrev_header = match self.search_debug_abbrev_sec(&header) {
            Some(h) => h,
            _ => return Err(Error::new(ErrorKind::NotFound, "Not found debug_abbrev section header"))
        };
        let debug_str = match self.search_debug_str(&header) {
            Some(h) => h,
            _ => return Err(Error::new(ErrorKind::NotFound, "Not found debug_str section header"))
        };

        // debug_infoセクションロード
        let f = File::open(&path)?;
        let mut reader = BufReader::new(f);
        self.debug_info.load(&mut reader, &debug_info_sec, &abbrev_header, &debug_str)?;

        // debug_lineセクションロード
        self.load_debug_line(path, header)?;

        Ok(())
    }

    /// load debug_line section
    fn load_debug_line(&mut self, path: &str, header: &[ElfSecHeader]) -> Result<()> {
        let line_h = match self.search_debug_line(&header) {
            Some(h) => h,
            _ => return Err(Error::new(ErrorKind::NotFound, "Not found debug_line section header"))
        };

        // stmt_listを抽出
        for cu_h in self.debug_info.get_header() {
            let stmt_list = cu_h.get_dies()
                                .iter()
                                .filter(|die| die.get_at_info() == DwAtInfo::StmtList)
                                .collect::<Vec<&DebugInfoEntry>>();
            // stmtに紐付いたdebug_lineセクションをロード
            for stmt in stmt_list {
                let mut line = DebugLineSection::new(line_h.get_offset());
                match stmt.get_data().parse::<u64>() {
                    Ok(offset) => line.load(path, offset)?,
                    Err(e) => panic!("[load_debug_line] cannot parse offset ({:?})", e)
                };
                // ロードした情報を保存
                self.debug_line.push(line)
            }
        }

        Ok(())
    }

    /// search debug_info section
    fn search_debug_info_sec<'a>(&self, header: &'a [ElfSecHeader]) -> Option<&'a ElfSecHeader> {
        header.iter().find(|s| s.get_name() == ".debug_info")
    }

    /// search debug_abbrev section
    fn search_debug_abbrev_sec<'a>(&self, header: &'a [ElfSecHeader]) -> Option<&'a ElfSecHeader> {
        header.iter().find(|s| s.get_name() == ".debug_abbrev")
    }

    /// search debug_str section
    fn search_debug_str<'a>(&self, header: &'a [ElfSecHeader]) -> Option<&'a ElfSecHeader> {
        header.iter().find(|s| s.get_name() == ".debug_str")
    }

    /// search debug_line section
    fn search_debug_line<'a>(&self, header: &'a [ElfSecHeader]) -> Option<&'a ElfSecHeader> {
        header.iter().find(|s| s.get_name() == ".debug_line")
    }
}

