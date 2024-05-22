use endian_codec::{DecodeLE, EncodeLE, PackedSize};
use windows::core::GUID;

#[derive(Debug)]
pub struct SectionInfos {
    pub base: usize,
    pub size: usize,
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Default, EncodeLE)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct ARGS_BUFFER {
    pub arg1: usize,
    pub arg2: usize,
    pub arg3: usize,
    pub arg4: usize,
    pub arg5: usize,
    pub arg6: usize,
    pub arg7: usize,
    pub arg8: usize,
    pub arg9: usize,
    pub arg10: usize,
    pub arg11: usize,
    pub arg12: usize,
    pub arg13: usize,
    pub arg14: usize,
} 

#[derive(Debug, PackedSize, DecodeLE, Clone, Default, EncodeLE)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct RPC_CLIENT_INTERFACE {
    pub Length: u32,
    pub InterfaceId: RPC_SYNTAX_IDENTIFIER,
    pub TransferSyntax: RPC_SYNTAX_IDENTIFIER,
    pub DispatchTable: usize,
    pub RpcProtseqEndpointCount: u32,
    pub RpcProtseqEndpoint: usize,
    pub Reserved: usize,
    pub InterpreterInfo: usize,
    pub Flags: u32,
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, Default, EncodeLE)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct RPC_DISPATCH_TABLE {
    pub DispatchTableCount: u32,
    pub DispatchTable: usize,
    pub Reserved: isize,
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, Default, EncodeLE)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct MIDL_SERVER_INFO {
    pub pStubDesc: usize,
    pub DispatchTable: usize,
    pub ProcString: usize,
    pub FmtStringOffset: usize,
    pub ThunkTable: usize,
    pub pTransferSyntax: usize,
    pub nCount: usize,
    pub pSyntaxInfo: usize,
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, Default, EncodeLE)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct MIDL_STUB_DESC {

    pub RpcInterfaceInformation: usize,
    pub pfnAllocate: usize,
    pub pfnFree: usize,
    pub IMPLICIT_HANDLE_INFO: usize,
    pub apfnNdrRundownRoutines: usize,
    pub aGenericBindingRoutinePairs: usize,
    pub apfnExprEval: usize,
    pub aXmitQuintuple: usize,
    pub pFormatTypes: usize,
    pub fCheckBounds: i32,
    pub Version: u32,
    pub pMallocFreeStruct: usize,
    pub MIDLVersion: i32,
    pub CommFaultOffsets: usize,
    pub aUserMarshalQuadruple: usize,
    pub NotifyRoutineTable: usize,
    pub mFlags: usize,
    pub CsRoutineTables: usize,
    pub ProxyServerInfo: usize,
    pub pExprInfo: usize,
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, Default, EncodeLE)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct RPC_MESSAGE {
    pub Handle: usize,
    pub DataRepresentation: u32,
    pub Buffer: usize,
    pub BufferLength: u32,
    pub ProcNum: u32,
    pub TransferSyntax: usize,
    pub RpcInterfaceInformation: usize,
    pub ReservedForRuntime: usize,
    pub ManagerEpv: usize,
    pub ImportContext: usize,
    pub RpcFlags: u32,
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, Default, PartialEq, Eq, Hash, EncodeLE)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct _GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, Default, EncodeLE)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct RPC_SYNTAX_IDENTIFIER {
    pub SyntaxGUID: _GUID,
    pub SyntaxVersion: RPC_VERSION,
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, Default, EncodeLE)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct RPC_VERSION {
    pub MajorVersion: u16,
    pub MinorVersion: u16,
}


#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, Default)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C, packed(8))]
pub struct STDOBJREF {
    pub flags: u32,
    pub cPublicRefs: u32,
    pub oxid: u64,
    pub oid: u64,
    pub ipid: u128,
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, Default)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct DUALSTRINGARRAY {
    pub wNumEntries: u16,
    pub wSecurityOffset: u16,
    pub aStringArray: u16,
}

#[derive(Debug, Clone, Copy, Default)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct OBJREF {
    pub signature: u32,
    pub flags: u32,
    pub iid: GUID,
    pub std: STDOBJREF,
    pub saResAddr: DUALSTRINGARRAY,
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, PartialEq)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct tagIPIDEntry {
    pub pNextIPID: usize,  // next IPIDEntry for same object
    pub dwFlags: u32,      // flags (see IPIDFLAGS)
    cStrongRefs: u32,      // strong reference count
    cWeakRefs: u32,        // weak reference count
    cPrivateRefs: u32,     // private reference count
    pv: usize,             // real interface pointer
    pStub: usize,          // proxy or stub pointer
    pub pOXIDEntry: usize, // ptr to OXIDEntry in OXID Table
    pub ipid: u128,        // interface pointer identifier
    iid: u128,             // interface iid
    pChnl: usize,          // channel pointer
    pIRCEntry: usize,      // reference cache line
    pInterfaceName: usize,
    pOIDFLink: usize, // In use OID list
    pOIDBLink: usize,
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, PartialEq)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct OXIDEntry {
    flink: usize,
    blink: usize,
    m_isInList: u64,
    info: [u8; 0x98],
    mid: u64,
    ipid_rundown: u128,
    pub oxid: u64,
    oid: u64,
}

/*
    [+0x000] _flink           : 0x1285663b220 [Type: CListElement *]
    [+0x008] _blink           : 0x0 [Type: CListElement *]
    [+0x010] m_isInList       : true [Type: bool]
    [+0x018] _info            [Type: wil::unique_struct<__MIDL_ILocalObjectExporter_0007,void (__cdecl*)(__MIDL_ILocalObjectExporter_0007 *),&ClearOxidInfo,std::nullptr_t,0>]
    [+0x0b0] _mid             : 0x9a72972955744076 [Type: unsigned __int64]
    [+0x0b8] _ipidRundown     : {00008800-08B8-0000-2FDA-F75294C4814D} [Type: _GUID]
    [+0x0c8] _moxid           : {B32D7849-1503-6431-7640-74552997729A} [Type: _GUID]
    [+0x0d8] _registered      : true [Type: std::atomic<bool>]
    [+0x0d9] _stopped         : false [Type: std::atomic<bool>]
    [+0x0da] _pendingRelease  : false [Type: std::atomic<bool>]
    [+0x0db] _remotingInitialized : true [Type: std::atomic<bool>]
    [+0x0e0] _hServerSTA      : 0x0 [Type: HWND__ *]
    [+0x0e8] _pParentApt      : 0x1285660d4e0 [Type: CComApartment *]
    [+0x0f0] _pSharedDefaultHandle : 0x0 [Type: CChannelHandle *]
    [+0x0f8] _pAuthId         : 0x0 [Type: void *]
    [+0x100] _dwAuthnSvc      : 0xffffffff [Type: unsigned long]
    [+0x108] _pMIDEntry       : 0x128566c3830 [Type: MIDEntry *]
    [+0x110] _pRUSTA          : 0x0 [Type: IRemUnknown *]
    [+0x118] _cRefs           : 0x69c [Type: unsigned long]
    [+0x120] _hComplete       : 0x1a0 [Type: void *]
    [+0x128] _cCalls          : 0 [Type: long]
    [+0x12c] _cResolverRef    : 0 [Type: long]
    [+0x130] _dwExpiredTime   : 0x0 [Type: unsigned long]
    [+0x138] _pAppContainerServerSecurityDescriptor : 0x0 [Type: void *]
    [+0x140] _ulMarshaledTargetInfoLength : 0x0 [Type: unsigned long]
    [+0x148] _marshaledTargetInfo : empty [Type: std::unique_ptr<unsigned char [0],DeleteMarshaledTargetInfo>]
    [=0x7ff8cdc888b0] _palloc          [Type: CPageAllocator]
    [+0x150] _clientDependencyEvaluated : false [Type: std::atomic<bool>]
    [+0x158] _pPrimaryOxid    : {...} [Type: std::atomic<OXIDEntry *>]
*/

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, PartialEq)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
struct tagPageEntry {
    pNext: usize,
    dwFlag: u32,
}

#[derive(Default)]
#[repr(C)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct tagCTXVERSION {
    ThisVerion: u16,
    MinVersion: u16,
}

#[derive(Default)]
#[repr(C, packed)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct tagCTXCOMMONHDR {
    ContextId: u128,
    Flags: u32,
    Reserved: u32,
    dwNumExtents: u32,
    cbExtents: u32,
    MshFlags: u32,
}

#[derive(Default)]
#[repr(C, packed)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct tagBYREFHDR {
    Reserved: u32,
    ProcessId: u32,
    pub guidProcessSecret: u128,
    pub pServerCtx: usize, // CObjectContext
}

#[derive(Default)]
#[repr(C)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct tagCONTEXTHEADER {
    pub Version: tagCTXVERSION,
    pub CommonHeader: tagCTXCOMMONHDR,
    pub ByRefHeader: tagBYREFHDR,
}

#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(transparent)]
pub struct IMAGE_FILE_MACHINE {
    pub machine: u16,
}

#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(transparent)]
pub struct IMAGE_FILE_CHARACTERISTICS {
    pub characteristics: u16,
}

#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: IMAGE_FILE_MACHINE,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: IMAGE_FILE_CHARACTERISTICS,
}

#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(transparent)]
pub struct IMAGE_OPTIONAL_HEADER_MAGIC {
    pub header: u16,
}

#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(transparent)]
pub struct IMAGE_SUBSYSTEM {
    pub subsystem: u16,
}

#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(transparent)]
pub struct IMAGE_DLL_CHARACTERISTICS {
    pub characteristics: u16,
}

#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[derive(PackedSize, Clone, Debug, Copy, DecodeLE)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C, packed(4))]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: IMAGE_SUBSYSTEM,
    pub DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(transparent)]
pub struct IMAGE_SECTION_CHARACTERISTICS {
    pub characteristics: u32,
}

#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct IMAGE_SECTION_HEADER_0 {
    // Its an union, but we don't care about the PhysicalAddress, and both are u32
    //pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: IMAGE_SECTION_HEADER_0,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: IMAGE_SECTION_CHARACTERISTICS,
}

#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}
