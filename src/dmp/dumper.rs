use std::{ffi::c_void, mem::size_of, ptr::{null, null_mut}};

use windows::{core::PCSTR, Win32::{
    Foundation::{CloseHandle, HANDLE, NTSTATUS},
    Storage::FileSystem::{
        CreateFileA, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
    },
}};

#[derive(Debug)]
pub enum DumpError {
    CreateFileError,
    DebuggerNotEnabled,
}

#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
struct SYSDBG_LIVEDUMP_CONTROL {
    Version: u32,
    BugCheckCode: u32,
    BugCheckParam1: u64,
    BugCheckParam2: u64,
    BugCheckParam3: u64,
    BugCheckParam4: u64,
    FileHandle: HANDLE,
    CancelHandle: HANDLE,
    Flags: u32,
    Pages: u32,
}

#[link(name = "ntdll.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "C" {
    #[link_name = "NtSystemDebugControl"]
    fn NtSystemDebugControl(
        command: usize,
        input_buffer: *const SYSDBG_LIVEDUMP_CONTROL,
        input_buffer_length: usize,
        output_buffer: *const c_void,
        output_buffer_len: usize,
        return_length: *mut usize,
    ) -> NTSTATUS;
}

pub fn create_dump_file(path: String) -> Result<(), DumpError> {
    let file_handle = unsafe {
        CreateFileA(
            PCSTR(format!("{}\0", path).as_ptr()),
            0x10000000,
            FILE_SHARE_MODE(0),
            None,
            FILE_CREATION_DISPOSITION(2),
            FILE_FLAGS_AND_ATTRIBUTES(0x80),
            HANDLE::default(),
        ).map_err(|_| DumpError::CreateFileError)?
    };

    let dump_control = SYSDBG_LIVEDUMP_CONTROL {
        Version: 1,
        BugCheckCode: 0x161,
        BugCheckParam1: 0,
        BugCheckParam2: 0,
        BugCheckParam3: 0,
        BugCheckParam4: 0,
        FileHandle: file_handle,
        CancelHandle: HANDLE::default(),
        Flags: 4,
        Pages: 0,
    };

    let status = unsafe {
        NtSystemDebugControl(
            37,
            &dump_control,
            size_of::<SYSDBG_LIVEDUMP_CONTROL>(),
            null(),
            0,
            null_mut(),
        )
    };

    if status.is_err() {
        println!("NTSTATUS : {:#X}", status.0);
        return Err(DumpError::DebuggerNotEnabled);
    }

    unsafe { CloseHandle(file_handle).unwrap() };

    Ok(())
}
