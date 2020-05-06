use std::fs::File;
use std::io::{Read, BufReader, Seek, SeekFrom, Result, Error, ErrorKind};

use crate::elf::elf::ElfSecHeader;
use crate::elf::leb128::ULEB128;

/// DW_TAG情報
#[derive(Debug)]
enum DwTagInfo {
    DwTagUnknown, // 不明
    DwTagArrayType,
    DwTagClassType,
    DwTagEntryPoint,
    DwTagEnumerationType,
    DwTagFormalParamter,
    DwTagImportedDeclaration,
    DwTagLabel,
    DwTagLexicalBlock,
    DwTagMember,
    DwTagPointerType,
    DwTagReferenceType,
    DwTagCompileUnit,
    DwTagStringType,
    DwTagStructureType,
    DwTagSubroutineType,
    DwTagTypedef,
    DwTagUnionType,
    DwTagUnspecifiedParameters,
    DwTagVariant,
    DwTagCommonBlock,
    DwTagCommonInclusion,
    DwTagInheritance,
    DwTagInlinedSubroutine,
    DwTagModule,
    DwTagPtrToMemberType,
    DwTagSetType,
    DwTagSubrangeType,
    DwTagWithStmt,
    DwTagAccessDeclaration,
    DwTagBaseType,
    DwTagCatchBlock,
    DwTagConstType,
    DwTagConstant,
    DwTagEnumerator,
    DwTagFileType,
    DwTagFriend,
    DwTagNamelist,
    DwTagNamelistItem,
    DwTagPackedType,
    DwTagSubprogram,
    DwTagTemplateTypeParameter,
    DwTagTemplateValueParameter,
    DwTagThrownType,
    DwTagTryBlock,
    DwTagVariantPart,
    DwTagVariable,
    DwTagVolatileType,
    // DWARF 3 values
    DwTagDwarfProceduer,
    DwTagRestritctType,
    DwTagInterfaceType,
    DwTagNamespace,
    DwTagImportedModule,
    DwTagUnspecifiedType,
    DwTagPartialUnit,
    DwTagImportedUnit,
    DwTagCondition,
    DwTagSharedType,
    // DWARF 4 values
    DwTagTypeUnit,
    DwTagRvalueReferenceType,
    DwTagTemplateAlias,
    DwTagLoUser,
    DwTagHiUser,
}

/// DW_AT情報
#[derive(Debug)]
enum DwAtInfo {
    DwAtUnknown, // 不明
    DwAtSibling,
    DwAtLocation,
    DwAtName,
    DwAtOrdering,
    DwAtSubscrData,
    DwAtByteSize,
    DwAtBitOffset,
    DwAtBitSize,
    DwAtElementList,
    DwAtStmtList,
    DwAtLowPc,
    DwAtHighPc,
    DwAtLanguage,
    DwAtMember,
    DwAtDiscr,
    DwAtDiscrValue,
    DwAtVisibility,
    DwAtImport,
    DwAtStringLength,
    DwAtCommonReference,
    DwAtCompDir,
    DwAtConstValue,
    DwAtContainingType,
    DwAtDefaultValue,
    DwAtInline,
    DwAtIsOptional,
    DwAtLowerBound,
    DwAtProducer,
    DwAtPrototyped,
    DwAtReturnAddr,
    DwAtStartScope,
    DwAtBitStride,
    DwAtUpperBound,
    DwAtAbstractOrigin,
    DwAtAccessibility,
    DwAtAddressClass,
    DwAtArtificial,
    DwAtBaseTypes,
    DwAtCallingConvention,
    DwAtCount,
    DwAtDataMemberLocation,
    DwAtDeclColumn,
    DwAtDeclFile,
    DwAtDeclLine,
    DwAtDeclaration,
    DwAtDiscrList,
    DwAtEncoding,
    DwAtExternal,
    DwAtFrameBase,
    DwAtFriend,
    DwAtIdentifierCase,
    DwAtMacroInfo,
    DwAtNamelistItems,
    DwAtPriority,
    DwAtSegment,
    DwAtSpecification,
    DwAtStaticLink,
    DwAtType,
    DwAtUseLocation,
    DwAtVariableParameter,
    DwAtVirtuality,
    DwAtVtableElemLocation,
    // DWARF 3 values
    DwAtAllocated,
    DwAtAssociated,
    DwAtDataLocation,
    DwAtByteStride,
    DwAtEntryPc,
    DwAtUseUTF8,
    DwAtExtension,
    DwAtRanges,
    DwAtTrampoline,
    DwAtCallColumn,
    DwAtCallFile,
    DwAtCallLine,
    DwAtDescription,
    DwAtBinaryScale,
    DwAtDecimalScale,
    DwAtSmall,
    DwAtDecimalSign,
    DwAtDigitCount,
    DwAtPictureString,
    DwAtMutable,
    DwAtThreadsScaled,
    DwAtExplicit,
    DwAtObjectPointer,
    DwAtEndianity,
    DwAtElemental,
    DwAtPure,
    DwAtRecursive,
    // DWARF 4 values
    DwAtSignature,
    DwAtMainSubprogram,
    DwAtDataBitOffset,
    DwAtConstExpr,
    DwAtEnumClass,
    DwAtLinkageName,
    DwAtEnd, // 終了attr
}

/// DW_FORM情報
#[derive(Debug)]
enum DwFormInfo {
    DwFormUnknown, // 不明
    DwFormAddr,
    DwFormBlock2,
    DwFormBlock4,
    DwFormData2,
    DwFormData4,
    DwFormData8,
    DwFormString,
    DwFormBlock,
    DwFormBlock1,
    DwFormData1,
    DwFormFlag,
    DwFormSdata,
    DwFormStrp,
    DwFormUdata,
    DwFormRefAddr,
    DwFormRef1,
    DwFormRef2,
    DwFormRef4,
    DwFormRef8,
    DwFormRefUdata,
    DwFormIndirect,
    // dwarf4
    DwFormSecOffset,
    DwFormExprloc,
    DwFormFlagPresent,
    DwFormRefSig8,
    DwFormEnd, // 終了form
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
            self.to_dw_tag(self.tag),
            self.to_has_child(self.has_child)
        );
        for (n, f) in self.attr_name.iter().zip(self.attr_form.iter()) {
            println!("    {:?} {:?}", self.to_dw_at(*n), self.to_dw_form(*f));
        }
    }

    /// DW_TAGコンバート
    fn to_dw_tag(&self, tag: u64) -> DwTagInfo {
        match tag {
            0x1  => DwTagInfo::DwTagArrayType,
            0x2  => DwTagInfo::DwTagClassType,
            0x3  => DwTagInfo::DwTagEntryPoint,
            0x4  => DwTagInfo::DwTagEnumerationType,
            0x5  => DwTagInfo::DwTagFormalParamter,
            0x8  => DwTagInfo::DwTagImportedDeclaration,
            0xA  => DwTagInfo::DwTagLabel,
            0xB  => DwTagInfo::DwTagLexicalBlock,
            0xD  => DwTagInfo::DwTagMember,
            0xF  => DwTagInfo::DwTagPointerType,
            0x10 => DwTagInfo::DwTagReferenceType,
            0x11 => DwTagInfo::DwTagCompileUnit,
            0x12 => DwTagInfo::DwTagStringType,
            0x13 => DwTagInfo::DwTagStructureType,
            0x15 => DwTagInfo::DwTagSubroutineType,
            0x16 => DwTagInfo::DwTagTypedef,
            0x17 => DwTagInfo::DwTagUnionType,
            0x18 => DwTagInfo::DwTagUnspecifiedParameters,
            0x19 => DwTagInfo::DwTagVariant,
            0x1A => DwTagInfo::DwTagCommonBlock,
            0x1B => DwTagInfo::DwTagCommonInclusion,
            0x1C => DwTagInfo::DwTagInheritance,
            0x1D => DwTagInfo::DwTagInlinedSubroutine,
            0x1E => DwTagInfo::DwTagModule,
            0x1F => DwTagInfo::DwTagPtrToMemberType,
            0x20 => DwTagInfo::DwTagSetType,
            0x21 => DwTagInfo::DwTagSubrangeType,
            0x22 => DwTagInfo::DwTagWithStmt,
            0x23 => DwTagInfo::DwTagAccessDeclaration,
            0x24 => DwTagInfo::DwTagBaseType,
            0x25 => DwTagInfo::DwTagCatchBlock,
            0x26 => DwTagInfo::DwTagConstType,
            0x27 => DwTagInfo::DwTagConstant,
            0x28 => DwTagInfo::DwTagEnumerator,
            0x29 => DwTagInfo::DwTagFileType,
            0x2A => DwTagInfo::DwTagFriend,
            0x2B => DwTagInfo::DwTagNamelist,
            0x2C => DwTagInfo::DwTagNamelistItem,
            0x2D => DwTagInfo::DwTagPackedType,
            0x2E => DwTagInfo::DwTagSubprogram,
            0x2F => DwTagInfo::DwTagTemplateTypeParameter,
            0x30 => DwTagInfo::DwTagTemplateValueParameter,
            0x31 => DwTagInfo::DwTagThrownType,
            0x32 => DwTagInfo::DwTagTryBlock,
            0x33 => DwTagInfo::DwTagVariantPart,
            0x34 => DwTagInfo::DwTagVariable,
            0x35 => DwTagInfo::DwTagVolatileType,
            0x36 => DwTagInfo::DwTagDwarfProceduer,
            0x37 => DwTagInfo::DwTagRestritctType,
            0x38 => DwTagInfo::DwTagInterfaceType,
            0x39 => DwTagInfo::DwTagNamespace,
            0x3A => DwTagInfo::DwTagImportedModule,
            0x3B => DwTagInfo::DwTagUnspecifiedType,
            0x3C => DwTagInfo::DwTagPartialUnit,
            0x3D => DwTagInfo::DwTagImportedUnit,
            0x3F => DwTagInfo::DwTagCondition,
            0x40 => DwTagInfo::DwTagSharedType,
            0x41 => DwTagInfo::DwTagTypeUnit,
            0x42 => DwTagInfo::DwTagRvalueReferenceType,
            0x43 => DwTagInfo::DwTagTemplateAlias,
            0x4080 => DwTagInfo::DwTagLoUser,
            0xFFFF => DwTagInfo::DwTagHiUser,
            _ =>  DwTagInfo::DwTagUnknown,
        }
    }

    /// has childコンバート
    fn to_has_child(&self, c: u8) -> &str {
        match c {
            1 => "has children",
            _ => "no children"
        }
    }

    /// DW_ATコンバート
    fn to_dw_at(&self, at: u64) -> DwAtInfo {
        match at {
            0x0  => DwAtInfo::DwAtEnd,
            0x1  => DwAtInfo::DwAtSibling,
            0x2  => DwAtInfo::DwAtLocation,
            0x3  => DwAtInfo::DwAtName,
            0x9  => DwAtInfo::DwAtOrdering,
            0xA => DwAtInfo::DwAtSubscrData,
            0xB => DwAtInfo::DwAtByteSize,
            0xC => DwAtInfo::DwAtBitOffset,
            0xD => DwAtInfo::DwAtBitSize,
            0xF => DwAtInfo::DwAtElementList,
            0x10 => DwAtInfo::DwAtStmtList,
            0x11 => DwAtInfo::DwAtLowPc,
            0x12 => DwAtInfo::DwAtHighPc,
            0x13 => DwAtInfo::DwAtLanguage,
            0x14 => DwAtInfo::DwAtMember,
            0x15 => DwAtInfo::DwAtDiscr,
            0x16 => DwAtInfo::DwAtDiscrValue,
            0x17 => DwAtInfo::DwAtVisibility,
            0x18 => DwAtInfo::DwAtImport,
            0x19 => DwAtInfo::DwAtStringLength,
            0x1A => DwAtInfo::DwAtCommonReference,
            0x1B => DwAtInfo::DwAtCompDir,
            0x1C => DwAtInfo::DwAtConstValue,
            0x1D => DwAtInfo::DwAtContainingType,
            0x1E => DwAtInfo::DwAtDefaultValue,
            0x20 => DwAtInfo::DwAtInline,
            0x21 => DwAtInfo::DwAtIsOptional,
            0x22 => DwAtInfo::DwAtLowerBound,
            0x25 => DwAtInfo::DwAtProducer,
            0x27 => DwAtInfo::DwAtPrototyped,
            0x2A => DwAtInfo::DwAtReturnAddr,
            0x2C => DwAtInfo::DwAtStartScope,
            0x2E => DwAtInfo::DwAtBitStride,
            0x2F => DwAtInfo::DwAtUpperBound,
            0x31 => DwAtInfo::DwAtAbstractOrigin,
            0x32 => DwAtInfo::DwAtAccessibility,
            0x33 => DwAtInfo::DwAtAddressClass,
            0x34 => DwAtInfo::DwAtArtificial,
            0x35 => DwAtInfo::DwAtBaseTypes,
            0x36 => DwAtInfo::DwAtCallingConvention,
            0x37 => DwAtInfo::DwAtCount,
            0x38 => DwAtInfo::DwAtDataMemberLocation,
            0x39 => DwAtInfo::DwAtDeclColumn,
            0x3A => DwAtInfo::DwAtDeclFile,
            0x3B => DwAtInfo::DwAtDeclLine,
            0x3C => DwAtInfo::DwAtDeclaration,
            0x3D => DwAtInfo::DwAtDiscrList,
            0x3E => DwAtInfo::DwAtEncoding,
            0x3F => DwAtInfo::DwAtExternal,
            0x40 => DwAtInfo::DwAtFrameBase,
            0x41 => DwAtInfo::DwAtFriend,
            0x42 => DwAtInfo::DwAtIdentifierCase,
            0x43 => DwAtInfo::DwAtMacroInfo,
            0x44 => DwAtInfo::DwAtNamelistItems,
            0x45 => DwAtInfo::DwAtPriority,
            0x46 => DwAtInfo::DwAtSegment,
            0x47 => DwAtInfo::DwAtSpecification,
            0x48 => DwAtInfo::DwAtStaticLink,
            0x49 => DwAtInfo::DwAtType,
            0x4A => DwAtInfo::DwAtUseLocation,
            0x4B => DwAtInfo::DwAtVariableParameter,
            0x4C => DwAtInfo::DwAtVirtuality,
            0x4D => DwAtInfo::DwAtVtableElemLocation,
            0x4E => DwAtInfo::DwAtAllocated,
            0x4F => DwAtInfo::DwAtAssociated,
            0x50 => DwAtInfo::DwAtDataLocation,
            0x51 => DwAtInfo::DwAtByteStride,
            0x52 => DwAtInfo::DwAtEntryPc,
            0x53 => DwAtInfo::DwAtUseUTF8,
            0x54 => DwAtInfo::DwAtExtension,
            0x55 => DwAtInfo::DwAtRanges,
            0x56 => DwAtInfo::DwAtTrampoline,
            0x57 => DwAtInfo::DwAtCallColumn,
            0x58 => DwAtInfo::DwAtCallFile,
            0x59 => DwAtInfo::DwAtCallLine,
            0x5A => DwAtInfo::DwAtDescription,
            0x5B => DwAtInfo::DwAtBinaryScale,
            0x5C => DwAtInfo::DwAtDecimalScale,
            0x5D => DwAtInfo::DwAtSmall,
            0x5E => DwAtInfo::DwAtDecimalSign,
            0x5F => DwAtInfo::DwAtDigitCount,
            0x60 => DwAtInfo::DwAtPictureString,
            0x61 => DwAtInfo::DwAtMutable,
            0x62 => DwAtInfo::DwAtThreadsScaled,
            0x63 => DwAtInfo::DwAtExplicit,
            0x64 => DwAtInfo::DwAtObjectPointer,
            0x65 => DwAtInfo::DwAtEndianity,
            0x66 => DwAtInfo::DwAtElemental,
            0x67 => DwAtInfo::DwAtPure,
            0x68 => DwAtInfo::DwAtRecursive,
            0x69 => DwAtInfo::DwAtSignature,
            0x6A => DwAtInfo::DwAtMainSubprogram,
            0x6B => DwAtInfo::DwAtDataBitOffset,
            0x6C => DwAtInfo::DwAtConstExpr,
            0x6D => DwAtInfo::DwAtEnumClass,
            0x6E => DwAtInfo::DwAtLinkageName,
            _ =>  DwAtInfo::DwAtUnknown,
        }
    }

    /// DW_FROMコンバート
    fn to_dw_form(&self, form: u64) -> DwFormInfo {
        match form {
            0x0  => DwFormInfo::DwFormEnd,
            0x1  => DwFormInfo::DwFormAddr,
            0x3  => DwFormInfo::DwFormBlock2,
            0x4  => DwFormInfo::DwFormBlock4,
            0x5  => DwFormInfo::DwFormData2,
            0x6  => DwFormInfo::DwFormData4,
            0x7  => DwFormInfo::DwFormData8,
            0x8 => DwFormInfo::DwFormString,
            0x9 => DwFormInfo::DwFormBlock,
            0xA => DwFormInfo::DwFormBlock1,
            0xB => DwFormInfo::DwFormData1,
            0xC => DwFormInfo::DwFormFlag,
            0xD => DwFormInfo::DwFormSdata,
            0xE  => DwFormInfo::DwFormStrp,
            0xF => DwFormInfo::DwFormUdata,
            0x10 => DwFormInfo::DwFormRefAddr,
            0x11 => DwFormInfo::DwFormRef1,
            0x12 => DwFormInfo::DwFormRef2,
            0x13 => DwFormInfo::DwFormRef4,
            0x14 => DwFormInfo::DwFormRef8,
            0x15 => DwFormInfo::DwFormRefUdata,
            0x16 => DwFormInfo::DwFormIndirect,
            0x17 => DwFormInfo::DwFormSecOffset,
            0x18 => DwFormInfo::DwFormExprloc,
            0x19 => DwFormInfo::DwFormFlagPresent,
            0x20 => DwFormInfo::DwFormRefSig8,
            _ =>  DwFormInfo::DwFormUnknown,
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
            abbrev.abbrev_no = DebugAbbRevSection::decode(reader).unwrap().1;

            // noがゼロならば、abbrevは終了
            if 0 == abbrev.abbrev_no {
                break;
            }
            abbrev.tag = DebugAbbRevSection::decode(reader).unwrap().1;

            // has_childは1byte
            let mut b = [0; 1];
            reader.read_exact(&mut b)?;
            abbrev.has_child = u8::from_le_bytes(b);

            // attribute/formコードをロード（name=0x00, form=0x00までループ)
            loop {
                let attr_name = DebugAbbRevSection::decode(reader).unwrap().1;
                let attr_form = DebugAbbRevSection::decode(reader).unwrap().1;
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

/// debug_info header(32bit mode)
#[derive(Debug)]
struct CUHeader {
    len: u32,            // debug_info length(for 32bit dwarf format. 0xFFFF_FFFF when 64bit dwarf mode)
    actual_len: u64,     // debug_info length(for 64bit mode)
    version: u16,        // dwarf version
    abb_rev_offset: u32, // debug_abbrev section offset in .debug_abbrev
    address_size: u8,    // 1-byte unsigned integer representing the size in bytes of an address on the target architecture(pointer size)
}

impl CUHeader {
    /// コンストラクタ
    pub fn new() -> Self {
        CUHeader {
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
        println!(".debug_info compile unit header:");
        println!("    length      : 0x{:x}", self.len);
        println!("    version     : 0x{:x}", self.version);
        println!("    abb offset  : 0x{:x}", self.abb_rev_offset);
        println!("    address size: 0x{:x}", self.address_size);
    }
}

/// debug_infoセクション
///
/// header/dies/abbrevは、インデックスで対応付け
#[derive(Debug)]
struct DebugInfoSection {
    header: Vec<CUHeader>,
    dies: Vec<Vec<u64>>,
    abbrev: Vec<DebugAbbRevSection>
}

impl DebugInfoSection {
    /// コンストラクタ
    pub fn new() -> Self {
        DebugInfoSection {
            header: vec![],
            dies: vec![],
            abbrev: vec![],
        }
    }

    /// debug_infoセクションロード
    fn load(&mut self, reader: &mut BufReader<File>, info_h: &ElfSecHeader, abbrev_h: &ElfSecHeader) -> Result<()> {
        // debug_infoセクションへ移動
        reader.seek(SeekFrom::Start(info_h.get_offset()))?;

        // CU Headerを読み込み、CUの情報をロードする
        let mut read_size = 0;
        loop {
            let mut cu_h = CUHeader::new();
            let mut cu_size = 0;

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
            cu_size += 2;

            // abb_rev offset
            reader.read_exact(&mut word)?;
            cu_h.abb_rev_offset = u32::from_le_bytes(word);
            read_size += 4;
            cu_size += 4;

            // address size
            let mut byte = [0; 1];
            reader.read_exact(&mut byte)?;
            cu_h.address_size = u8::from_le_bytes(byte);
            read_size += 1;
            cu_size += 1;

            // DIEをロード
            let mut dies = vec![];
            loop {
                let (size, abbrev_no) = DebugAbbRevSection::decode(reader).unwrap();
                dies.push(abbrev_no);
                read_size += size;
                cu_size += size;

                // すべてのDIEを読み込めば終了
                if cu_h.len == cu_size as u32 {
                    break;
                }
            }

            // ロードした情報を保存
            self.header.push(cu_h);
            self.dies.push(dies);

            // debug_infoセクションすべてを読み込めば終了
            if read_size == info_h.get_size() {
                break;
            }
        }

        // 対応するabbrevセクションをロード
        for cu_h in &self.header {
            let mut abbrev = DebugAbbRevSection::new();
            abbrev.load(reader, &abbrev_h, cu_h.abb_rev_offset.into())?;
            self.abbrev.push(abbrev);
        }

        Ok(())
    }
}

/// Dwarf情報
pub struct Dwarf {
    debug_info: DebugInfoSection,
}

impl ULEB128 for Dwarf {}
impl Dwarf {
    /// コンストラクタ
    pub fn new() -> Self {
        Dwarf {
            debug_info: DebugInfoSection::new(),
        }
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

        // debug_infoセクションロード
        let f = File::open(&path)?;
        let mut reader = BufReader::new(f);
        self.debug_info.load(&mut reader, &debug_info_sec, &abbrev_header)?;

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
}

