//! Section Header structures and parsing.

use crate::prelude::*;
use crate::reader::ReadAt;
use crate::{Error, Result};

/// Section characteristics flags.
pub mod characteristics {
    /// `IMAGE_SCN_CNT_CODE`: the section contains executable code.
    pub const CODE: u32 = 0x0000_0020;
    /// `IMAGE_SCN_CNT_INITIALIZED_DATA`: the section contains initialized data.
    pub const INITIALIZED_DATA: u32 = 0x0000_0040;
    /// `IMAGE_SCN_CNT_UNINITIALIZED_DATA`: the section contains uninitialized (zero-filled) data.
    pub const UNINITIALIZED_DATA: u32 = 0x0000_0080;
    /// `IMAGE_SCN_LNK_INFO`: the section contains comments or linker directives (object files only).
    pub const LINK_INFO: u32 = 0x0000_0200;
    /// `IMAGE_SCN_LNK_REMOVE`: the section is not included in the image (object files only).
    pub const LINK_REMOVE: u32 = 0x0000_0800;
    /// `IMAGE_SCN_LNK_COMDAT`: the section contains COMDAT data (object files only).
    pub const LINK_COMDAT: u32 = 0x0000_1000;
    /// `IMAGE_SCN_GPREL`: the section contains data referenced through the global pointer.
    pub const GPREL: u32 = 0x0000_8000;
    /// `IMAGE_SCN_ALIGN_1BYTES`: align data on a 1-byte boundary (object files only).
    pub const ALIGN_1BYTES: u32 = 0x0010_0000;
    /// `IMAGE_SCN_ALIGN_2BYTES`: align data on a 2-byte boundary (object files only).
    pub const ALIGN_2BYTES: u32 = 0x0020_0000;
    /// `IMAGE_SCN_ALIGN_4BYTES`: align data on a 4-byte boundary (object files only).
    pub const ALIGN_4BYTES: u32 = 0x0030_0000;
    /// `IMAGE_SCN_ALIGN_8BYTES`: align data on an 8-byte boundary (object files only).
    pub const ALIGN_8BYTES: u32 = 0x0040_0000;
    /// `IMAGE_SCN_ALIGN_16BYTES`: align data on a 16-byte boundary (object files only).
    pub const ALIGN_16BYTES: u32 = 0x0050_0000;
    /// `IMAGE_SCN_ALIGN_32BYTES`: align data on a 32-byte boundary (object files only).
    pub const ALIGN_32BYTES: u32 = 0x0060_0000;
    /// `IMAGE_SCN_ALIGN_64BYTES`: align data on a 64-byte boundary (object files only).
    pub const ALIGN_64BYTES: u32 = 0x0070_0000;
    /// `IMAGE_SCN_ALIGN_128BYTES`: align data on a 128-byte boundary (object files only).
    pub const ALIGN_128BYTES: u32 = 0x0080_0000;
    /// `IMAGE_SCN_ALIGN_256BYTES`: align data on a 256-byte boundary (object files only).
    pub const ALIGN_256BYTES: u32 = 0x0090_0000;
    /// `IMAGE_SCN_ALIGN_512BYTES`: align data on a 512-byte boundary (object files only).
    pub const ALIGN_512BYTES: u32 = 0x00A0_0000;
    /// `IMAGE_SCN_ALIGN_1024BYTES`: align data on a 1024-byte boundary (object files only).
    pub const ALIGN_1024BYTES: u32 = 0x00B0_0000;
    /// `IMAGE_SCN_ALIGN_2048BYTES`: align data on a 2048-byte boundary (object files only).
    pub const ALIGN_2048BYTES: u32 = 0x00C0_0000;
    /// `IMAGE_SCN_ALIGN_4096BYTES`: align data on a 4096-byte boundary (object files only).
    pub const ALIGN_4096BYTES: u32 = 0x00D0_0000;
    /// `IMAGE_SCN_ALIGN_8192BYTES`: align data on an 8192-byte boundary (object files only).
    pub const ALIGN_8192BYTES: u32 = 0x00E0_0000;
    /// `IMAGE_SCN_LNK_NRELOC_OVFL`: the section contains extended relocations (count stored in the first relocation).
    pub const NRELOC_OVFL: u32 = 0x0100_0000;
    /// `IMAGE_SCN_MEM_DISCARDABLE`: the section can be discarded as needed.
    pub const DISCARDABLE: u32 = 0x0200_0000;
    /// `IMAGE_SCN_MEM_NOT_CACHED`: the section cannot be cached.
    pub const NOT_CACHED: u32 = 0x0400_0000;
    /// `IMAGE_SCN_MEM_NOT_PAGED`: the section is not pageable.
    pub const NOT_PAGED: u32 = 0x0800_0000;
    /// `IMAGE_SCN_MEM_SHARED`: the section can be shared in memory.
    pub const SHARED: u32 = 0x1000_0000;
    /// `IMAGE_SCN_MEM_EXECUTE`: the section can be executed as code.
    pub const EXECUTE: u32 = 0x2000_0000;
    /// `IMAGE_SCN_MEM_READ`: the section can be read.
    pub const READ: u32 = 0x4000_0000;
    /// `IMAGE_SCN_MEM_WRITE`: the section can be written to.
    pub const WRITE: u32 = 0x8000_0000;
}

/// `IMAGE_SECTION_HEADER`: one 40-byte entry of the section table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SectionHeader {
    /// Section name, UTF-8, null-padded to 8 bytes (not null-terminated if exactly 8 bytes).
    pub name: [u8; 8],
    /// Size of the section when loaded into memory, in bytes.
    pub virtual_size: u32,
    /// RVA of the first byte of the section when loaded into memory.
    pub virtual_address: u32,
    /// Size of the initialized data on disk, in bytes (multiple of `FileAlignment`).
    pub size_of_raw_data: u32,
    /// File offset of the section's first page on disk; 0 for uninitialized-only sections.
    pub pointer_to_raw_data: u32,
    /// File offset of the section's COFF relocation entries (0 for images).
    pub pointer_to_relocations: u32,
    /// File offset of the section's COFF line-number entries (deprecated, normally 0).
    pub pointer_to_linenumbers: u32,
    /// Number of COFF relocation entries for the section (0 for images).
    pub number_of_relocations: u16,
    /// Number of COFF line-number entries for the section (deprecated, normally 0).
    pub number_of_linenumbers: u16,
    /// Section flags; see [`characteristics`].
    pub characteristics: u32,
}

impl SectionHeader {
    /// Size of an encoded `IMAGE_SECTION_HEADER`, in bytes.
    pub const SIZE: usize = 40;

    /// Get the section name as a string (trimmed of null bytes).
    ///
    /// PE section names are not guaranteed to be valid UTF-8. This method
    /// returns a `Cow<str>` that will be borrowed if the name is valid UTF-8,
    /// or owned with lossy conversion if it contains invalid bytes.
    #[must_use]
    pub fn name_str(&self) -> Cow<'_, str> {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end])
    }

    /// Get the section name as raw bytes (without null padding).
    #[must_use]
    pub fn name_bytes(&self) -> &[u8] {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        &self.name[..end]
    }

    /// Set the section name from a string.
    pub fn set_name(&mut self, name: &str) {
        self.name = [0u8; 8];
        let bytes = name.as_bytes();
        let len = bytes.len().min(8);
        self.name[..len].copy_from_slice(&bytes[..len]);
    }

    /// Check if the section is executable.
    #[must_use]
    pub fn is_executable(&self) -> bool {
        self.characteristics & characteristics::EXECUTE != 0
    }

    /// Check if the section is readable.
    #[must_use]
    pub fn is_readable(&self) -> bool {
        self.characteristics & characteristics::READ != 0
    }

    /// Check if the section is writable.
    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.characteristics & characteristics::WRITE != 0
    }

    /// Check if the section contains code.
    #[must_use]
    pub fn contains_code(&self) -> bool {
        self.characteristics & characteristics::CODE != 0
    }

    /// Check if this RVA falls within this section.
    #[must_use]
    pub fn contains_rva(&self, rva: u32) -> bool {
        let size = self.virtual_size.max(self.size_of_raw_data);
        rva.checked_sub(self.virtual_address)
            .is_some_and(|offset| offset < size)
    }

    /// Convert an RVA to file offset within this section.
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        let section_offset = rva.checked_sub(self.virtual_address)?;
        if self.pointer_to_raw_data == 0 || section_offset >= self.size_of_raw_data {
            return None;
        }
        self.pointer_to_raw_data.checked_add(section_offset)
    }

    /// Parse a section header from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }

        let mut name = [0u8; 8];
        name.copy_from_slice(&data[0..8]);

        Ok(Self {
            name,
            virtual_size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            virtual_address: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            size_of_raw_data: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            pointer_to_raw_data: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            pointer_to_relocations: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            pointer_to_linenumbers: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            number_of_relocations: u16::from_le_bytes([data[32], data[33]]),
            number_of_linenumbers: u16::from_le_bytes([data[34], data[35]]),
            characteristics: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
        })
    }

    /// Write the section header to a buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if `buf` is shorter than [`Self::SIZE`].
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        let Some(dest) = buf.get_mut(..Self::SIZE) else {
            return Err(Error::buffer_too_small(Self::SIZE, buf.len()));
        };
        dest.copy_from_slice(&self.encode());
        Ok(())
    }

    /// Encode the header into its 40-byte on-disk representation.
    fn encode(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..8].copy_from_slice(&self.name);
        buf[8..12].copy_from_slice(&self.virtual_size.to_le_bytes());
        buf[12..16].copy_from_slice(&self.virtual_address.to_le_bytes());
        buf[16..20].copy_from_slice(&self.size_of_raw_data.to_le_bytes());
        buf[20..24].copy_from_slice(&self.pointer_to_raw_data.to_le_bytes());
        buf[24..28].copy_from_slice(&self.pointer_to_relocations.to_le_bytes());
        buf[28..32].copy_from_slice(&self.pointer_to_linenumbers.to_le_bytes());
        buf[32..34].copy_from_slice(&self.number_of_relocations.to_le_bytes());
        buf[34..36].copy_from_slice(&self.number_of_linenumbers.to_le_bytes());
        buf[36..40].copy_from_slice(&self.characteristics.to_le_bytes());
        buf
    }

    /// Parse a section header from a positional reader at the given offset.
    ///
    /// # Errors
    ///
    /// Returns an error if the reader cannot supply [`Self::SIZE`] bytes at
    /// `offset`.
    pub fn read_from<R: ReadAt>(reader: &R, offset: u64) -> Result<Self> {
        let mut buf = [0u8; Self::SIZE];
        reader.read_exact_at(offset, &mut buf)?;
        Self::parse(&buf)
    }

    /// Read multiple section headers from a positional reader.
    ///
    /// # Errors
    ///
    /// Returns an error if a header offset overflows `u64` or if the reader
    /// cannot supply `count` consecutive headers starting at `offset`.
    pub fn read_sections<R: ReadAt>(reader: &R, offset: u64, count: usize) -> Result<Vec<Self>> {
        let mut sections = Vec::with_capacity(count);
        for i in 0..count {
            let relative_offset = i
                .checked_mul(Self::SIZE)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or_else(|| Error::invalid_section("section-table size overflow"))?;
            let section_offset = offset
                .checked_add(relative_offset)
                .ok_or_else(|| Error::invalid_section("section-table offset overflow"))?;
            sections.push(Self::read_from(reader, section_offset)?);
        }
        Ok(sections)
    }

    /// Serialize to a byte vector.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode().to_vec()
    }
}

/// A section with its header and owned data.
/// This is the main type for working with sections during PE modification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Section header (will be updated during layout).
    pub header: SectionHeader,
    /// Raw section data (owned).
    pub data: Vec<u8>,
    /// Original raw extent when `data` came from a loader-mapped image.
    pub(crate) mapped_raw_size: Option<u32>,
    pub(crate) mapped_data_len: usize,
}

impl Section {
    /// Create a new section with the given name and characteristics.
    #[must_use]
    pub fn new(name: &str, characteristics: u32) -> Self {
        let mut header = SectionHeader {
            name: [0u8; 8],
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics,
        };
        header.set_name(name);
        Self {
            header,
            data: Vec::new(),
            mapped_raw_size: None,
            mapped_data_len: 0,
        }
    }

    /// Create a section from a header and data.
    #[must_use]
    pub fn from_header_and_data(header: SectionHeader, data: Vec<u8>) -> Self {
        Self {
            header,
            data,
            mapped_raw_size: None,
            mapped_data_len: 0,
        }
    }

    /// Create a section from bytes copied out of a loader-mapped image.
    pub(crate) fn from_mapped_header_and_data(header: SectionHeader, data: Vec<u8>) -> Self {
        let mapped_data_len = data.len();
        Self {
            mapped_raw_size: Some(header.size_of_raw_data),
            mapped_data_len,
            header,
            data,
        }
    }

    /// Get the section name.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        self.header.name_str()
    }

    /// Set the section data.
    ///
    /// # Panics
    ///
    /// Panics if `data.len()` exceeds `u32::MAX`; use
    /// [`Self::try_set_data`] for a fallible update.
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.try_set_data(data)
            .expect("section data exceeds u32: use try_set_data() for fallible updates");
    }

    /// Set section data after checking that its virtual size is representable.
    ///
    /// # Errors
    ///
    /// Returns an error if `data.len()` exceeds `u32::MAX`; the section is
    /// left unchanged in that case.
    pub fn try_set_data(&mut self, data: Vec<u8>) -> Result<()> {
        let size = u32::try_from(data.len())
            .map_err(|_| Error::invalid_section("section data exceeds u32"))?;
        self.data = data;
        self.mapped_raw_size = None;
        self.mapped_data_len = 0;
        self.header.virtual_size = size;
        Ok(())
    }

    /// Append data to the section.
    ///
    /// # Panics
    ///
    /// Panics if the combined data length exceeds `u32::MAX`; use
    /// [`Self::try_append_data`] for a fallible update.
    pub fn append_data(&mut self, data: &[u8]) {
        self.try_append_data(data)
            .expect("section data exceeds u32: use try_append_data() for fallible updates");
    }

    /// Append bytes and return their section-relative offset.
    ///
    /// # Errors
    ///
    /// Returns an error if the combined data length exceeds `u32::MAX`; the
    /// section is left unchanged in that case.
    pub fn try_append_data(&mut self, data: &[u8]) -> Result<u32> {
        let offset = u32::try_from(self.data.len())
            .map_err(|_| Error::invalid_section("section data exceeds u32"))?;
        let new_len = self
            .data
            .len()
            .checked_add(data.len())
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(|| Error::invalid_section("section data exceeds u32"))?;
        self.data.extend_from_slice(data);
        self.mapped_raw_size = None;
        self.mapped_data_len = 0;
        self.header.virtual_size = new_len;
        Ok(offset)
    }

    /// Mark every byte in this section as initialized raw-file data.
    ///
    /// Mapped-image parsing retains virtual zero-fill in `data` while
    /// remembering the smaller original raw extent. Call this after editing
    /// that virtual tail when it should be emitted to a rebuilt file.
    ///
    /// # Panics
    ///
    /// Panics if `data.len()` exceeds `u32::MAX`, which can only happen when
    /// `data` was replaced directly with an oversized buffer.
    pub fn materialize_virtual_data(&mut self) {
        self.mapped_raw_size = None;
        self.mapped_data_len = 0;
        self.header.virtual_size = u32::try_from(self.data.len())
            .expect("parsed section data is always representable as u32");
    }

    pub(crate) fn preserved_raw_size(&self) -> Option<u32> {
        (self.data.len() == self.mapped_data_len)
            .then_some(self.mapped_raw_size)
            .flatten()
    }

    /// Check if an RVA falls within this section.
    #[must_use]
    pub fn contains_rva(&self, rva: u32) -> bool {
        self.header.contains_rva(rva)
    }

    /// Get data at an RVA offset within this section.
    #[must_use]
    pub fn data_at_rva(&self, rva: u32, len: usize) -> Option<&[u8]> {
        if !self.contains_rva(rva) {
            return None;
        }
        let offset = rva.checked_sub(self.header.virtual_address)? as usize;
        let end = offset.checked_add(len)?;
        if end <= self.data.len() {
            Some(&self.data[offset..end])
        } else {
            None
        }
    }

    /// Get mutable data at an RVA offset within this section.
    pub fn data_at_rva_mut(&mut self, rva: u32, len: usize) -> Option<&mut [u8]> {
        if !self.contains_rva(rva) {
            return None;
        }
        let offset = rva.checked_sub(self.header.virtual_address)? as usize;
        let end = offset.checked_add(len)?;
        if end <= self.data.len() {
            Some(&mut self.data[offset..end])
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_header_size() {
        assert_eq!(SectionHeader::SIZE, 40);
    }

    #[test]
    fn test_section_header_name() {
        let mut header = SectionHeader {
            name: [0u8; 8],
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0,
        };
        header.set_name(".text");
        assert_eq!(header.name_str(), ".text");
    }

    #[test]
    fn test_section_header_roundtrip() {
        let original = SectionHeader {
            name: *b".text\0\0\0",
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            size_of_raw_data: 0x200,
            pointer_to_raw_data: 0x200,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: characteristics::CODE
                | characteristics::EXECUTE
                | characteristics::READ,
        };

        let bytes = original.to_bytes();
        let parsed = SectionHeader::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_section_new() {
        let section = Section::new(".test", characteristics::READ | characteristics::WRITE);
        assert_eq!(section.name(), ".test");
        assert!(section.header.is_readable());
        assert!(section.header.is_writable());
    }

    #[test]
    fn test_section_data_at_rva() {
        let mut section = Section::new(".data", characteristics::READ);
        section.header.virtual_address = 0x2000;
        section.set_data(vec![0x11, 0x22, 0x33, 0x44, 0x55]);

        assert!(section.contains_rva(0x2000));
        assert!(section.contains_rva(0x2004));
        assert!(!section.contains_rva(0x1FFF));
        assert!(!section.contains_rva(0x2005));

        assert_eq!(section.data_at_rva(0x2001, 2), Some(&[0x22, 0x33][..]));
        assert_eq!(section.data_at_rva(0x2000, 10), None); // too long
    }

    #[test]
    fn test_rva_to_offset_excludes_virtual_only_data() {
        let header = SectionHeader {
            name: *b".data\0\0\0",
            virtual_size: 0x1000,
            virtual_address: 0x2000,
            size_of_raw_data: 0x200,
            pointer_to_raw_data: 0x400,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: characteristics::INITIALIZED_DATA | characteristics::READ,
        };

        assert!(header.contains_rva(0x2200));
        assert_eq!(header.rva_to_offset(0x21ff), Some(0x5ff));
        assert_eq!(header.rva_to_offset(0x2200), None);
    }
}
