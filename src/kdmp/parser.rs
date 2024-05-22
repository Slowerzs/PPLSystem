use std::{
    cmp,
    collections::HashMap,
    fmt::UpperHex,
    mem::size_of,
    ops::{Add, BitAnd, Shl, Shr},
    usize,
};

use windows::Win32::System::Diagnostics::Debug::DUMP_HEADER64;

use crate::irundown::locate::get_com_data_section_info;

use super::structs::BitmapHeader;

#[derive(Debug)]
pub enum ParsingError {
    BadAlignment,
    BufferTooSmall,
    BadSignature,
    BadDumpType,
}

#[derive(Debug)]
pub enum PageError {
    RangeTooLong,
    PageNotInDump,
}

pub struct PageEntry {
    value: u64,
}

impl PageEntry {
    pub fn from(value: u64) -> Self {
        Self { value: value }
    }

    pub fn is_present(&self) -> bool {
        (self.value & 1) != 0
    }

    pub fn is_large_page(&self) -> bool {
        (self.value & 128) != 0
    }

    pub fn get_page_frame_number(&self) -> u64 {
        (self.value & PAGE_FRAME_NUMBER_MASK) >> PAGE_FRAME_NUMBER_BITSHIFT
    }
}

#[derive(Eq, PartialEq, Hash, Debug, Clone, Copy)]
pub struct PhysicalAddress {
    addr: u64,
}

#[derive(Eq, PartialEq, Hash, Debug, Clone, Copy)]
pub struct VirtualAddress {
    pub addr: u64,
}

impl PhysicalAddress {
    pub fn from(addr: u64) -> Self {
        PhysicalAddress { addr: addr }
    }
}

impl UpperHex for VirtualAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.addr.fmt(f)
    }
}
impl UpperHex for PhysicalAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.addr.fmt(f)
    }
}

impl VirtualAddress {
    pub fn from(addr: u64) -> Self {
        VirtualAddress { addr: addr }
    }

    pub fn get_pml4_offset(&self) -> u64 {
        ((self.addr & PML4_INDEX_MASK) >> PML4_INDEX_BITSHIFT) << 3
    }

    pub fn get_pdpt_offset(&self) -> u64 {
        ((self.addr & PDPT_INDEX_MASK) >> PDPT_INDEX_BITSHIFT) << 3
    }

    pub fn get_pdt_offset(&self) -> u64 {
        ((self.addr & PD_INDEX_MASK) >> PD_INDEX_BITSHIFT) << 3
    }

    pub fn get_pt_offset(&self) -> u64 {
        ((self.addr & PT_INDEX_MASK) >> PT_INDEX_BITSHIFT) << 3
    }

    pub fn get_offset(&self) -> u64 {
        self.addr & PT_OFFSET_MASK
    }

    pub fn get_large_page_offset(&self) -> u64 {
        self.addr & 0x1fffff
    }
}

impl Add for VirtualAddress {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            addr: self.addr + rhs.addr,
        }
    }
}

impl Add<u64> for VirtualAddress {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Self {
            addr: self.addr + rhs,
        }
    }
}
impl Add for PhysicalAddress {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            addr: self.addr + rhs.addr,
        }
    }
}

impl Add<u64> for PhysicalAddress {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Self {
            addr: self.addr + rhs,
        }
    }
}

impl BitAnd<u64> for PhysicalAddress {
    type Output = Self;

    fn bitand(self, rhs: u64) -> Self {
        Self {
            addr: self.addr & rhs,
        }
    }
}

impl BitAnd<u64> for VirtualAddress {
    type Output = Self;

    fn bitand(self, rhs: u64) -> Self {
        Self {
            addr: self.addr & rhs,
        }
    }
}

impl Shl<usize> for PhysicalAddress {
    type Output = Self;

    fn shl(self, rhs: usize) -> Self::Output {
        Self {
            addr: self.addr << rhs,
        }
    }
}

impl Shl<usize> for VirtualAddress {
    type Output = Self;

    fn shl(self, rhs: usize) -> Self::Output {
        Self {
            addr: self.addr << rhs,
        }
    }
}

impl Shr<usize> for PhysicalAddress {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        Self {
            addr: self.addr >> rhs,
        }
    }
}

impl Shr<usize> for VirtualAddress {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        Self {
            addr: self.addr >> rhs,
        }
    }
}

const PAGE_FRAME_NUMBER_MASK: u64 =
    0b0000000000000000_111111111111111111111111111111111111_000000000000;
const PAGE_FRAME_NUMBER_BITSHIFT: usize = 12;

const PML4_INDEX_MASK: u64 = 0b0000000000000000_111111111_000000000000000000000000000000000000000;
const PML4_INDEX_BITSHIFT: usize = 39;
const PDPT_INDEX_MASK: u64 = 0b0000000000000000000000000_111111111_000000000000000000000000000000;
const PDPT_INDEX_BITSHIFT: usize = 30;
const PD_INDEX_MASK: u64 = 0b0000000000000000000000000000000000_111111111_000000000000000000000;
const PD_INDEX_BITSHIFT: usize = 21;
const PT_INDEX_MASK: u64 = 0b0000000000000000000000000000000000000000000_111111111_000000000000;
const PT_INDEX_BITSHIFT: usize = 12;
const PT_OFFSET_MASK: u64 = 0b00000000000000000000000000000000000000000000000000000_111111111111;

const PAGE_SIZE: usize = 0x1000;

pub trait Parsable<'a> {
    fn read_physical_memory(
        &self,
        phys_addr: PhysicalAddress,
        len: usize,
    ) -> Result<&[u8], PageError>;
    fn read_physical_memory_page(&self, phys_addr: PhysicalAddress) -> Result<&[u8], PageError>;
    fn from_buffer(buf: &'a [u8]) -> Result<Self, ParsingError>
    where
        Self: Sized;
    fn read_virtual_memory_page(
        &self,
        pml4: PhysicalAddress,
        virt_addr: VirtualAddress,
    ) -> Result<&[u8], PageError>;
    fn read_virtual_memory(
        &self,
        pml4: PhysicalAddress,
        virt_addr: VirtualAddress,
        len: usize,
    ) -> Result<Vec<u8>, PageError>;
    fn get_ipid_table(&self, process_directory_base: PhysicalAddress) -> Option<u64>;
}

pub struct DmpParser<'a> {
    pub buffer: &'a [u8],
    pub pages: HashMap<PhysicalAddress, usize>,
    pub directory_table_base: PhysicalAddress,
    pub ps_active_process_list: VirtualAddress,
}

impl<'a> Parsable<'a> for DmpParser<'a> {
    fn from_buffer(buf: &'a [u8]) -> Result<Self, ParsingError> {
        let dmp_headers = get_dump_headers_from_buffer(buf)?;

        let bitmap_header =
            get_bitmap_headers_from_buffer(&buf[size_of::<DUMP_HEADER64>()..buf.len()])?;

        let mut dmp_pages: HashMap<PhysicalAddress, usize> = HashMap::new();

        let mut current_page = bitmap_header.FirstPage as usize;
        let bitmap_size = bitmap_header.Pages / 8;

        let bitmap_data = &buf[(size_of::<DUMP_HEADER64>() + size_of::<BitmapHeader>())..buf.len()];

        for bitmap_index in 0..bitmap_size {
            let byte = bitmap_data[bitmap_index as usize];

            for bit_index in 0..8 {
                let bit = (byte >> bit_index) & 1;
                if bit != 0 {
                    let pfn = (bitmap_index * 8) + bit_index as u64;
                    let pa = pfn * PAGE_SIZE as u64;

                    dmp_pages.insert(PhysicalAddress::from(pa), current_page);

                    current_page += PAGE_SIZE;
                }
            }
        }

        let dmp = DmpParser {
            buffer: buf,
            pages: dmp_pages,
            directory_table_base: PhysicalAddress::from(dmp_headers.DirectoryTableBase),
            ps_active_process_list: VirtualAddress::from(dmp_headers.PsActiveProcessHead),
        };

        Ok(dmp)
    }

    fn read_physical_memory_page(&self, phys_addr: PhysicalAddress) -> Result<&[u8], PageError> {
        let page_offset = self
            .pages
            .get(&phys_addr)
            .ok_or_else(|| PageError::PageNotInDump)?;

        Ok(&self.buffer[*page_offset..(page_offset + PAGE_SIZE)])
    }

    fn read_physical_memory(
        &self,
        phys_addr: PhysicalAddress,
        len: usize,
    ) -> Result<&[u8], PageError> {
        if ((phys_addr.addr & 0xFFF) as usize + len) > PAGE_SIZE {
            println!("Tried read @{:#X} for  {:#X}", phys_addr, len);
            return Err(PageError::RangeTooLong);
        }
        let data = self.read_physical_memory_page(phys_addr & !0xFFF)?;
        let start_offset = phys_addr.addr as usize % PAGE_SIZE;
        Ok(&data[start_offset..start_offset + len])
    }

    fn read_virtual_memory_page(
        &self,
        pml4: PhysicalAddress,
        virt_addr: VirtualAddress,
    ) -> Result<&[u8], PageError> {
        let page_frame_number = PageEntry::from(pml4.addr).get_page_frame_number();
        let pml4_base = PhysicalAddress::from(page_frame_number << 12);
        let pml4_offset = virt_addr.get_pml4_offset();

        let level4_entry_address = PhysicalAddress::from(pml4_base.addr + pml4_offset);

        let level4_entry_data = self.read_physical_memory(level4_entry_address, 0x8)?;
        let level4_entry = u64::from_le_bytes(level4_entry_data.try_into().unwrap());

        let pml4_entry = PageEntry::from(level4_entry);

        if !pml4_entry.is_present() {
            println!("Error level 4");
            return Err(PageError::PageNotInDump);
        }

        let pdpt_base = PhysicalAddress::from(pml4_entry.get_page_frame_number() << 12);
        let pdpt_offset = virt_addr.get_pdpt_offset();

        let pdpt_entry_address = PhysicalAddress::from(pdpt_base.addr + pdpt_offset);
        let pdpt_entry_data = self.read_physical_memory(pdpt_entry_address, 0x8)?;
        let pdpt_entry = u64::from_le_bytes(pdpt_entry_data.try_into().unwrap());

        let pdpt_entry = PageEntry::from(pdpt_entry);

        if !pdpt_entry.is_present() {
            println!("Error level 3");
            return Err(PageError::PageNotInDump);
        }

        let pdt_base = PhysicalAddress::from(pdpt_entry.get_page_frame_number() << 12);
        let pdt_offset = virt_addr.get_pdt_offset();

        let pdt_entry_address = PhysicalAddress::from(pdt_base.addr + pdt_offset);
        let pdt_entry_data = self.read_physical_memory(pdt_entry_address, 0x8)?;
        let pdt_entry = u64::from_le_bytes(pdt_entry_data.try_into().unwrap());

        let pdt_entry = PageEntry::from(pdt_entry);

        if !pdt_entry.is_present() {
            println!("Error level 2");
            return Err(PageError::PageNotInDump);
        }

        if pdt_entry.is_large_page() {
            let pt_base = PhysicalAddress::from(pdt_entry.get_page_frame_number() << 12);
            let pt_offset = virt_addr.get_large_page_offset();

            let pt_entry_address = PhysicalAddress::from((pt_base.addr + pt_offset) & !0xFFF);
            let pt_entry_data = self.read_physical_memory(pt_entry_address, PAGE_SIZE)?;

            return Ok(pt_entry_data);
        }

        let pt_base = PhysicalAddress::from(pdt_entry.get_page_frame_number() << 12);
        let pt_offset = virt_addr.get_pt_offset();

        let pt_entry_address = PhysicalAddress::from(pt_base.addr + pt_offset);
        let pt_entry_data = self.read_physical_memory(pt_entry_address, 0x8)?;
        let pt_entry = u64::from_le_bytes(pt_entry_data.try_into().unwrap());

        let pt_entry = PageEntry::from(pt_entry);

        if !pt_entry.is_present() {
            println!("Error level 1");
            return Err(PageError::PageNotInDump);
        }

        let page_base = PhysicalAddress::from(pt_entry.get_page_frame_number() << 12);

        let page_entry_data = self.read_physical_memory(page_base, PAGE_SIZE)?;
        Ok(page_entry_data)
    }

    fn read_virtual_memory(
        &self,
        pml4: PhysicalAddress,
        virt_addr: VirtualAddress,
        len: usize,
    ) -> Result<Vec<u8>, PageError> {
        let offset_to_page = PAGE_SIZE - (virt_addr.addr as usize % PAGE_SIZE);
        let beginning_len = cmp::min(len, offset_to_page);

        let mut beginning_data = self.read_virtual_memory_page(pml4, virt_addr)?.to_vec();
        beginning_data = beginning_data[(virt_addr.addr as usize % PAGE_SIZE)
            ..((virt_addr.addr as usize % PAGE_SIZE) + beginning_len)]
            .to_vec();

        let complete_pages = (len - beginning_len) / PAGE_SIZE;

        for i in 0..complete_pages {
            let mut page_addr = virt_addr + offset_to_page as u64;
            page_addr = page_addr + (i * PAGE_SIZE) as u64;

            beginning_data.extend_from_slice(self.read_virtual_memory_page(pml4, page_addr)?);
        }

        let ending_len = len - (beginning_len + (complete_pages * PAGE_SIZE));
        let ending_addr = VirtualAddress::from(
            virt_addr.addr + beginning_len as u64 + (complete_pages * PAGE_SIZE) as u64,
        );
        let ending_page = self.read_virtual_memory_page(pml4, ending_addr)?;
        let ending_page = &ending_page[..ending_len];

        beginning_data.extend_from_slice(ending_page);
        Ok(beginning_data)
    }

    fn get_ipid_table(&self, process_directory_base: PhysicalAddress) -> Option<u64> {
        let com_data_info = get_com_data_section_info()?;

        let _remote_com_section_data = self.read_virtual_memory(
            process_directory_base,
            VirtualAddress::from(com_data_info.base as u64),
            com_data_info.size,
        );

        Some(0)
    }

}

fn get_ref_from_buffer<T>(buf: &[u8]) -> Result<&T, ParsingError> {
    if buf.len() < size_of::<T>() {
        return Err(ParsingError::BufferTooSmall);
    }

    if (buf.as_ptr() as usize) % std::mem::align_of::<T>() != 0 {
        return Err(ParsingError::BadAlignment);
    }

    Ok(unsafe { &*(buf.as_ptr() as *const T) })
}

fn get_dump_headers_from_buffer(buf: &[u8]) -> Result<&DUMP_HEADER64, ParsingError> {
    let headers: &DUMP_HEADER64 = get_ref_from_buffer(buf)?;

    if headers.Signature != 0x45474150 {
        return Err(ParsingError::BadSignature);
    }

    if headers.ValidDump != 0x34365544 {
        return Err(ParsingError::BadSignature);
    }

    if headers.DumpType != 0x6 {
        return Err(ParsingError::BadDumpType);
    }

    Ok(headers)
}

fn get_bitmap_headers_from_buffer(buf: &[u8]) -> Result<&BitmapHeader, ParsingError> {
    let bitmap_headers: &BitmapHeader = get_ref_from_buffer(buf)?;

    if bitmap_headers.Signature != 0x504d4453 {
        return Err(ParsingError::BadSignature);
    }

    if bitmap_headers.ValidDump != 0x504d5544 {
        return Err(ParsingError::BadDumpType);
    }

    Ok(bitmap_headers)
}
