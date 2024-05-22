use crate::kdmp::parser::VirtualAddress;
use endian_codec::{DecodeLE, PackedSize};
use pdb::FallibleIterator;
use std::{fs, io::Cursor};
use symbolic::debuginfo::pe::PeObject;
use windows::{
    core::s,
    Win32::{Foundation::FreeLibrary, System::LibraryLoader::LoadLibraryA},
};

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, PartialEq, Default)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct CServerOID {
    padding: [u8; 0x18],
    pub oid: u64,
    pub cserveroxid: u64,
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, PartialEq)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct CServerOXID {
    pub padding: [u8; 0x18],
    pub oxid: u64,
    pub cprocess: u64,
    pub padding2: [u8; 0x38],
    pub ipid: u128,
}

#[derive(Debug, PackedSize, DecodeLE, Clone, Copy, PartialEq)]
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
pub struct CProcess {
    pub padding: [u8; 0x58],
    pub pid: u32,
}

pub fn locate_rpcss_oxid_list_head() -> Option<VirtualAddress> {
    let rpcss_base = unsafe { LoadLibraryA(s!("rpcss.dll\0")).ok()? };

    // FIXME
    let mut gp_server_oxid_table_offset = 0;

    let rpcss_data = fs::read(r"C:\Windows\System32\rpcss.dll").expect("Failed reading rpcss.dll");

    let rpcss_object = PeObject::parse(&rpcss_data).expect("Failed parsing rpcss.dll");

    let pdb_id = rpcss_object.debug_id().to_string().replace("-", "");

    let mut pdb_data: Vec<u8> = Vec::new();

    ureq::get(
        format!("https://msdl.microsoft.com/download/symbols/rpcss.pdb/{pdb_id}/rpcss.pdb")
            .as_str(),
    )
    .call()
    .expect("Failed downloading pdb for rpcss")
    .into_reader()
    .read_to_end(&mut pdb_data)
    .unwrap();

    let mut pdb_parser = pdb::PDB::open(Cursor::new(pdb_data)).expect("Failed parsing rpcss .PDB");

    let symbols_table = pdb_parser
        .global_symbols()
        .expect("Failed parsing rpcss.pdb");
    let addresses_table = pdb_parser.address_map().expect("Failed parsing rpcss.pdb");

    let mut symbols = symbols_table.iter();
    while let Some(symbol) = symbols.next().expect("Failed parsing pdb") {
        match symbol.parse() {
            Ok(pdb::SymbolData::Public(data)) => {


                // we found the location of a function!
                let rva = data.offset.to_rva(&addresses_table).unwrap_or_default();
                if data.name.to_string().contains("gpServerOxidTable") {
                    gp_server_oxid_table_offset = rva.0 as u64;
                    break;
                }
                
            }
            _ => {}
        }
    }

    let gp_server_oid_list =
        VirtualAddress::from(rpcss_base.0 as u64 + gp_server_oxid_table_offset);

    unsafe { FreeLibrary(rpcss_base).ok()? };

    Some(gp_server_oid_list)
}
