//! Base relocation table parsing and building.
//!
//! This module has types that read and write PE base relocation tables. The loader uses these
//! tables when it loads the image at an address that is not its preferred base.
//!
//! # Examples
//!
//! ## Listing relocations from a PE file
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! let relocs = pe.relocations()?;
//! for block in &relocs.blocks {
//!     println!("Block at page RVA {:#x}", block.page_rva);
//!     for entry in &block.entries {
//!         println!("  Type: {:?}, Offset: {:#x}",
//!             entry.reloc_type, entry.offset);
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Adding relocations to a PE file
//!
//! ```no_run
//! use portex::{PeImage, RelocationBlock, RelocationEntry, RelocationTable, RelocationType};
//!
//! # let file_bytes: &[u8] = &[];
//! let mut pe = PeImage::parse(file_bytes)?;
//!
//! // Make the relocation table from blocks.
//! let table = RelocationTable {
//!     blocks: vec![
//!         RelocationBlock {
//!             page_rva: 0x1000,
//!             block_size: 12, // 8-byte header + 2 entries * 2 bytes
//!             entries: vec![
//!                 RelocationEntry { reloc_type: RelocationType::Dir64, offset: 0x100 },
//!                 RelocationEntry { reloc_type: RelocationType::Dir64, offset: 0x200 },
//!             ],
//!         },
//!     ],
//! };
//!
//! // Write the relocations into the PE.
//! pe.update_relocations(&table, None)?;
//! let rebuilt = pe.try_build()?;
//! assert!(!rebuilt.is_empty());
//! # Ok::<(), portex::Error>(())
//! ```

use crate::prelude::*;
use crate::{Error, Result};

/// Base relocation types (`IMAGE_REL_BASED_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationType {
    /// No relocation (padding).
    Absolute,
    /// High 16 bits of a 32-bit address.
    High,
    /// Low 16 bits of a 32-bit address.
    Low,
    /// Full 32-bit address (HIGHLOW).
    HighLow,
    /// High 16 bits of a 32-bit address, adjusted for sign extension of the low half.
    HighAdj,
    /// Machine-specific (type 5): MIPS JMPADDR, ARM MOV32, RISC-V HIGH20.
    MachineSpecific5,
    /// Section index (reserved).
    Section,
    /// Machine-specific (type 7): REL32, THUMB MOV32, RISC-V LOW12I.
    MachineSpecific7,
    /// RISC-V low 12 bits, S-type format.
    RiscvLow12S,
    /// MIPS 16-bit jump address.
    MipsJmpAddr16,
    /// 64-bit address (DIR64).
    Dir64,
    /// Relocation type not known to this version of the crate.
    Unknown(u8),
}

impl RelocationType {
    /// Parse the type from the type bits (the high 4 bits of an entry).
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Absolute,
            1 => Self::High,
            2 => Self::Low,
            3 => Self::HighLow,
            4 => Self::HighAdj,
            5 => Self::MachineSpecific5,
            6 => Self::Section,
            7 => Self::MachineSpecific7,
            8 => Self::RiscvLow12S,
            9 => Self::MipsJmpAddr16,
            10 => Self::Dir64,
            other => Self::Unknown(other & 0x0f),
        }
    }

    /// Return the four-bit on-disk relocation code.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Absolute => 0,
            Self::High => 1,
            Self::Low => 2,
            Self::HighLow => 3,
            Self::HighAdj => 4,
            Self::MachineSpecific5 => 5,
            Self::Section => 6,
            Self::MachineSpecific7 => 7,
            Self::RiscvLow12S => 8,
            Self::MipsJmpAddr16 => 9,
            Self::Dir64 => 10,
            Self::Unknown(value) => value & 0x0f,
        }
    }
}

/// A single relocation entry in a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationEntry {
    /// Relocation type.
    pub reloc_type: RelocationType,
    /// Offset of the target from the page RVA of the block (12 bits).
    pub offset: u16,
}

impl RelocationEntry {
    /// Parse an entry from its 16-bit value.
    #[must_use]
    pub fn from_u16(value: u16) -> Self {
        // The type is the high four bits of the high byte.
        let [high, _] = value.to_be_bytes();
        Self {
            reloc_type: RelocationType::from_u8(high >> 4),
            offset: value & 0x0FFF,
        }
    }

    /// Convert the entry to its 16-bit value.
    #[must_use]
    pub fn to_u16(self) -> u16 {
        (u16::from(self.reloc_type.as_u8()) << 12) | (self.offset & 0x0FFF)
    }

    /// Check if this is a padding entry (`Absolute` type).
    #[must_use]
    pub fn is_padding(self) -> bool {
        matches!(self.reloc_type, RelocationType::Absolute)
    }
}

/// A block of relocations for a single 4-KiB page.
///
/// On disk, a block is an `IMAGE_BASE_RELOCATION` header (8 bytes) followed by its entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationBlock {
    /// RVA of the page (the base address for the relocations of this block).
    pub page_rva: u32,
    /// Total size of this block in bytes, including the header.
    pub block_size: u32,
    /// Relocation entries for this page.
    pub entries: Vec<RelocationEntry>,
}

impl RelocationBlock {
    /// Size of the `IMAGE_BASE_RELOCATION` header (`VirtualAddress` and
    /// `SizeOfBlock`) in bytes.
    pub const HEADER_SIZE: usize = Self::HEADER_SIZE_U32 as usize;
    /// [`Self::HEADER_SIZE`] as a `u32`, for arithmetic on directory sizes.
    const HEADER_SIZE_U32: u32 = 8;

    /// Parse a relocation block from bytes.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::BufferTooSmall` if `data` is shorter than the header or the declared
    /// block size.
    ///
    /// Returns an invalid-data-directory error in these conditions:
    ///
    /// - The block size is smaller than the header or is not a multiple of 4.
    /// - The page RVA is not aligned to 4 KiB.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some((&[p0, p1, p2, p3, s0, s1, s2, s3], body)) = data.split_first_chunk::<8>() else {
            return Err(Error::buffer_too_small(Self::HEADER_SIZE, data.len()));
        };

        let page_rva = u32::from_le_bytes([p0, p1, p2, p3]);
        let block_size_raw = u32::from_le_bytes([s0, s1, s2, s3]);

        let block_size = block_size_raw as usize;
        let Some(entries_size) = block_size
            .checked_sub(Self::HEADER_SIZE)
            .filter(|_| block_size.is_multiple_of(4))
        else {
            return Err(Error::invalid_data_directory(format!(
                "invalid base-relocation block size {block_size}"
            )));
        };
        if !page_rva.is_multiple_of(0x1000) {
            return Err(Error::invalid_data_directory(format!(
                "base-relocation page RVA {page_rva:#x} is not 4-KiB aligned"
            )));
        }

        let entry_bytes = body
            .get(..entries_size)
            .ok_or_else(|| Error::buffer_too_small(block_size, data.len()))?;
        // `entries_size` is even, so no bytes remain after the pairs.
        let (pairs, _) = entry_bytes.as_chunks::<2>();
        let entries = pairs
            .iter()
            .map(|pair| RelocationEntry::from_u16(u16::from_le_bytes(*pair)))
            .collect();

        Ok(Self {
            page_rva,
            block_size: block_size_raw,
            entries,
        })
    }

    /// Calculate the RVA of a specific entry. On overflow, the result saturates to
    /// `u32::MAX`.
    #[must_use]
    pub fn rva_for_entry(&self, entry: RelocationEntry) -> u32 {
        self.checked_rva_for_entry(entry).unwrap_or(u32::MAX)
    }

    /// Calculate the RVA of an entry. Returns `None` on overflow.
    #[must_use]
    pub fn checked_rva_for_entry(&self, entry: RelocationEntry) -> Option<u32> {
        self.page_rva.checked_add(u32::from(entry.offset))
    }

    /// Serialize the block to bytes.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_to_bytes`] fails.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("relocation block build failed: use try_to_bytes()")
    }

    /// Serialize the block to bytes, with a checked size and 12-bit offsets.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data-directory error in these conditions:
    ///
    /// - The page RVA is not aligned to 4 KiB.
    /// - An entry offset is wider than 12 bits, or an entry type is wider than 4 bits.
    /// - The target RVA of an entry overflows.
    /// - The block size is more than `u32::MAX`.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        if !self.page_rva.is_multiple_of(0x1000) {
            return Err(Error::invalid_data_directory(format!(
                "base-relocation page RVA {:#x} is not 4-KiB aligned",
                self.page_rva
            )));
        }
        for entry in &self.entries {
            if entry.offset > 0x0fff {
                return Err(Error::invalid_data_directory(format!(
                    "relocation offset {:#x} exceeds 12 bits",
                    entry.offset
                )));
            }
            if matches!(entry.reloc_type, RelocationType::Unknown(value) if value > 0x0f) {
                return Err(Error::invalid_data_directory(
                    "relocation type exceeds four bits",
                ));
            }
            self.page_rva
                .checked_add(u32::from(entry.offset))
                .ok_or_else(|| {
                    Error::invalid_data_directory("base-relocation target RVA overflow")
                })?;
        }
        // An odd entry count requires one IMAGE_REL_BASED_ABSOLUTE padding word.
        let needs_padding = !self.entries.len().is_multiple_of(2);
        let size = self
            .entries
            .len()
            .checked_add(usize::from(needs_padding))
            .and_then(|count| count.checked_mul(2))
            .and_then(|size| Self::HEADER_SIZE.checked_add(size))
            .ok_or_else(|| Error::invalid_data_directory("relocation block size overflow"))?;
        let size_u32 = u32::try_from(size)
            .map_err(|_| Error::invalid_data_directory("relocation block exceeds u32"))?;
        let mut buf = Vec::with_capacity(size);

        buf.extend_from_slice(&self.page_rva.to_le_bytes());
        buf.extend_from_slice(&size_u32.to_le_bytes());
        for entry in &self.entries {
            buf.extend_from_slice(&entry.to_u16().to_le_bytes());
        }
        if needs_padding {
            buf.extend_from_slice(&[0, 0]);
        }

        Ok(buf)
    }
}

/// The complete relocation table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelocationTable {
    /// List of relocation blocks.
    pub blocks: Vec<RelocationBlock>,
}

impl RelocationTable {
    /// Parse the relocation table of a PE file.
    ///
    /// - `reloc_rva` is the RVA from the data directory.
    /// - `reloc_size` is the size from the data directory.
    /// - `read_at_rva` is a closure that reads bytes at an RVA.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    ///
    /// - The closure cannot read a block.
    /// - A block fails [`RelocationBlock::parse`].
    /// - A block extends past `reloc_size`.
    /// - Nonzero bytes follow a truncated tail or an all-zero padding block.
    /// - An RVA or offset calculation overflows.
    pub fn parse<F>(reloc_rva: u32, reloc_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut blocks = Vec::new();
        let mut offset = 0u32;

        while offset < reloc_size {
            let entry_rva = reloc_rva.checked_add(offset).ok_or_else(|| {
                Error::invalid_data_directory("base-relocation table RVA overflow")
            })?;
            let remaining = reloc_size.checked_sub(offset).ok_or_else(|| {
                Error::invalid_data_directory("base-relocation table size underflow")
            })?;
            if remaining < RelocationBlock::HEADER_SIZE_U32 {
                let tail = crate::parse_utils::read_exact_rva(
                    &read_at_rva,
                    entry_rva,
                    remaining as usize,
                    "base-relocation tail",
                )?;
                if tail.iter().all(|byte| *byte == 0) {
                    break;
                }
                return Err(Error::invalid_data_directory(
                    "truncated base-relocation block header",
                ));
            }

            let header = crate::parse_utils::read_exact_rva(
                &read_at_rva,
                entry_rva,
                RelocationBlock::HEADER_SIZE,
                "base-relocation block header",
            )?;
            let [p0, p1, p2, p3, s0, s1, s2, s3] =
                <[u8; 8]>::try_from(header).map_err(|header| {
                    Error::buffer_too_small(RelocationBlock::HEADER_SIZE, header.len())
                })?;

            let page_rva = u32::from_le_bytes([p0, p1, p2, p3]);
            let block_size = u32::from_le_bytes([s0, s1, s2, s3]);

            // Some linkers fill the end of the declared directory with zeros.
            if page_rva == 0 && block_size == 0 {
                let tail = crate::parse_utils::read_exact_rva(
                    &read_at_rva,
                    entry_rva,
                    remaining as usize,
                    "base-relocation zero tail",
                )?;
                if tail.iter().all(|byte| *byte == 0) {
                    break;
                }
                return Err(Error::invalid_data_directory(
                    "zero base-relocation block is followed by nonzero data",
                ));
            }

            if block_size > remaining {
                return Err(Error::invalid_data_directory(format!(
                    "base-relocation block size {block_size} exceeds {remaining} remaining bytes"
                )));
            }
            let data = crate::parse_utils::read_exact_rva(
                &read_at_rva,
                entry_rva,
                block_size as usize,
                "base-relocation block",
            )?;

            let block = RelocationBlock::parse(&data)?;
            offset = offset.checked_add(block_size).ok_or_else(|| {
                Error::invalid_data_directory("base-relocation table size overflow")
            })?;
            if offset > reloc_size {
                return Err(Error::invalid_data_directory(format!(
                    "base-relocation block extends past directory size {reloc_size}"
                )));
            }
            blocks.push(block);
        }

        Ok(Self { blocks })
    }

    /// Check if the relocation table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Get the total number of relocations, without padding entries.
    #[must_use]
    pub fn relocation_count(&self) -> usize {
        self.blocks
            .iter()
            .flat_map(|b| &b.entries)
            .filter(|e| !e.is_padding())
            .count()
    }

    /// Apply all supported base relocations to `buffer`.
    ///
    /// The function fails on a malformed range. It also fails on an architecture-specific
    /// relocation that it cannot interpret generically.
    ///
    /// The fixups are modular: each target field wraps around at its own width, as the Windows
    /// loader does.
    ///
    /// Returns the number of relocations applied.
    ///
    /// # Errors
    ///
    /// Returns an invalid-RVA error if a target field is not inside `buffer`.
    ///
    /// Returns an invalid-data-directory error in these conditions:
    ///
    /// - A target RVA overflows.
    /// - A `HIGHADJ` entry does not have its adjustment word.
    /// - A `DIR64` entry occurs and `is_64bit` is false.
    /// - An entry has a machine-specific or unknown type.
    ///
    /// On error, `buffer` keeps the fixups that the function applied before the failed entry.
    pub fn try_apply(&self, buffer: &mut [u8], delta: i128, is_64bit: bool) -> Result<usize> {
        let mut applied = 0usize;
        for block in &self.blocks {
            let mut entries = block.entries.iter();
            while let Some(entry) = entries.next() {
                if entry.is_padding() {
                    continue;
                }

                let target_rva = block
                    .page_rva
                    .checked_add(u32::from(entry.offset))
                    .ok_or_else(|| {
                        Error::invalid_data_directory("base-relocation target RVA overflow")
                    })?;

                match entry.reloc_type {
                    RelocationType::HighLow => {
                        let field = target_field::<4>(buffer, target_rva)?;
                        let value = u32::from_le_bytes(*field);
                        write_wrapped(field, i128::from(value).wrapping_add(delta));
                    }
                    RelocationType::Dir64 if is_64bit => {
                        let field = target_field::<8>(buffer, target_rva)?;
                        let value = u64::from_le_bytes(*field);
                        write_wrapped(field, i128::from(value).wrapping_add(delta));
                    }
                    RelocationType::High => {
                        let field = target_field::<2>(buffer, target_rva)?;
                        let full = i128::from(u16::from_le_bytes(*field)) << 16;
                        write_wrapped(field, full.wrapping_add(delta) >> 16);
                    }
                    RelocationType::Low => {
                        let field = target_field::<2>(buffer, target_rva)?;
                        let value = u16::from_le_bytes(*field);
                        write_wrapped(field, i128::from(value).wrapping_add(delta));
                    }
                    RelocationType::HighAdj => {
                        let field = target_field::<2>(buffer, target_rva)?;
                        // The next entry holds the low half of the target, not a relocation.
                        let adjustment = entries.next().ok_or_else(|| {
                            Error::invalid_data_directory(
                                "HIGHADJ relocation is missing its adjustment word",
                            )
                        })?;
                        let low = i128::from(adjustment.to_u16().cast_signed());
                        let high = i128::from(u16::from_le_bytes(*field)) << 16;
                        let relocated = high
                            .wrapping_add(low)
                            .wrapping_add(delta)
                            .wrapping_add(0x8000);
                        write_wrapped(field, relocated >> 16);
                    }
                    RelocationType::Dir64 => {
                        return Err(Error::invalid_data_directory(
                            "DIR64 relocation appears in a PE32 image",
                        ));
                    }
                    unsupported => {
                        return Err(Error::invalid_data_directory(format!(
                            "relocation type {unsupported:?} requires machine-specific handling"
                        )));
                    }
                }
                // This cannot overflow: each entry adds one at most, and entries are in memory.
                applied += 1;
            }
        }
        Ok(applied)
    }

    /// Serialize the table to bytes.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_to_bytes`] fails.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("relocation table build failed: use try_to_bytes()")
    }

    /// Serialize each block, with checked arithmetic on the table size.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`RelocationBlock::try_to_bytes`]. Returns an
    /// invalid-data-directory error if the table is larger than `u32::MAX`.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        for block in &self.blocks {
            let bytes = block.try_to_bytes()?;
            output
                .len()
                .checked_add(bytes.len())
                .and_then(|size| u32::try_from(size).ok())
                .ok_or_else(|| {
                    Error::invalid_data_directory("base-relocation table exceeds u32")
                })?;
            output.extend(bytes);
        }
        Ok(output)
    }

    /// Calculate the total size of the serialized table.
    ///
    /// The size saturates at `usize::MAX`. A table in memory cannot reach this limit: each
    /// block and each entry uses more memory than its serialized form.
    #[must_use]
    pub fn calculate_size(&self) -> usize {
        self.blocks.iter().fold(0usize, |total, block| {
            let entry_count = block.entries.len();
            // Pad to a 4-byte boundary.
            let padded_count =
                entry_count.saturating_add(usize::from(!entry_count.is_multiple_of(2)));
            let block_size =
                RelocationBlock::HEADER_SIZE.saturating_add(padded_count.saturating_mul(2));
            total.saturating_add(block_size)
        })
    }

    /// Add a relocation entry at a specific RVA.
    pub fn add_relocation(&mut self, rva: u32, reloc_type: RelocationType) {
        let page_rva = rva & !0xFFF; // Round down to the 4-KiB page.
        // The offset is the low 12 bits of the RVA.
        let [low, high, ..] = rva.to_le_bytes();
        let offset = u16::from_le_bytes([low, high]) & 0x0FFF;
        let entry = RelocationEntry { reloc_type, offset };

        // Find or make the block for this page.
        if let Some(block) = self.blocks.iter_mut().find(|b| b.page_rva == page_rva) {
            block.entries.push(entry);
        } else {
            self.blocks.push(RelocationBlock {
                page_rva,
                block_size: 0, // Will be calculated on serialize
                entries: vec![entry],
            });
        }
    }

    /// Add a HIGHLOW (32-bit) relocation.
    pub fn add_highlow(&mut self, rva: u32) {
        self.add_relocation(rva, RelocationType::HighLow);
    }

    /// Add a DIR64 (64-bit) relocation.
    pub fn add_dir64(&mut self, rva: u32) {
        self.add_relocation(rva, RelocationType::Dir64);
    }

    /// Sort the blocks by page RVA, and pad each block to a 4-byte boundary.
    ///
    /// This function changes `self`.
    pub fn normalize(&mut self) {
        // Sort the blocks.
        self.blocks.sort_by_key(|b| b.page_rva);

        // Pad each block to a 4-byte boundary.
        for block in &mut self.blocks {
            if block.entries.len() % 2 == 1 {
                block.entries.push(RelocationEntry {
                    reloc_type: RelocationType::Absolute,
                    offset: 0,
                });
            }
            // Update block_size. If a block is too large for `u32`, the size saturates here.
            // `try_to_bytes` calculates the size again and rejects the block.
            block.block_size = block
                .entries
                .len()
                .checked_mul(2)
                .and_then(|size| size.checked_add(RelocationBlock::HEADER_SIZE))
                .and_then(|size| u32::try_from(size).ok())
                .unwrap_or(u32::MAX);
        }
    }

    /// Make a normalized copy. This function does not change `self`.
    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut copy = self.clone();
        copy.normalize();
        copy
    }

    /// Build the relocation table bytes from a normalized copy. This function does not change
    /// `self`.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] fails.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        self.try_build()
            .expect("relocation build failed: use try_build() for fallible serialization")
    }

    /// Build normalized relocation bytes, with checked block and table sizes.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::try_to_bytes`] for the normalized copy.
    pub fn try_build(&self) -> Result<Vec<u8>> {
        self.normalized().try_to_bytes()
    }
}

/// Return the `N`-byte target field at the RVA `rva` in `buffer`.
///
/// Returns an invalid-RVA error if the field is not fully inside `buffer`.
fn target_field<const N: usize>(buffer: &mut [u8], rva: u32) -> Result<&mut [u8; N]> {
    let start = rva as usize;
    let end = start
        .checked_add(N)
        .ok_or_else(|| Error::invalid_data_directory("relocation target range overflow"))?;
    buffer
        .get_mut(start..end)
        .and_then(|field| <&mut [u8; N]>::try_from(field).ok())
        .ok_or_else(|| Error::invalid_rva(rva))
}

/// Write the low `N` bytes of `value` in little-endian order.
///
/// This reduces `value` modulo 2^(8 * `N`), as relocation fixups require.
fn write_wrapped<const N: usize>(target: &mut [u8; N], value: i128) {
    for (byte, value_byte) in target.iter_mut().zip(value.to_le_bytes()) {
        *byte = value_byte;
    }
}

/// Builder for relocation tables.
///
/// This type gives a fluent interface to build relocation tables.
///
/// # Example
///
/// ```
/// use portex::reloc::RelocationBuilder;
///
/// let mut builder = RelocationBuilder::new();
///
/// // Add relocations. The builder groups them by page.
/// builder.add_dir64(0x1000);
/// builder.add_dir64(0x1008);
/// builder.add_highlow(0x2000);
///
/// let (data, size) = builder.build();
/// assert!(size > 0);
/// ```
#[derive(Debug, Clone, Default)]
pub struct RelocationBuilder {
    table: RelocationTable,
}

impl RelocationBuilder {
    /// Create a new relocation builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Make a builder from an existing relocation table.
    #[must_use]
    pub fn from_table(table: RelocationTable) -> Self {
        Self { table }
    }

    /// Add a relocation entry at a specific RVA.
    pub fn add_relocation(&mut self, rva: u32, reloc_type: RelocationType) -> &mut Self {
        self.table.add_relocation(rva, reloc_type);
        self
    }

    /// Add a HIGHLOW (32-bit) relocation.
    pub fn add_highlow(&mut self, rva: u32) -> &mut Self {
        self.table.add_highlow(rva);
        self
    }

    /// Add a DIR64 (64-bit) relocation.
    pub fn add_dir64(&mut self, rva: u32) -> &mut Self {
        self.table.add_dir64(rva);
        self
    }

    /// Get the number of relocations added.
    #[must_use]
    pub fn relocation_count(&self) -> usize {
        self.table.relocation_count()
    }

    /// Calculate the total size when serialized.
    #[must_use]
    pub fn calculate_size(&self) -> usize {
        self.table.normalized().calculate_size()
    }

    /// Build the relocation table. Returns `(data, size)`.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] fails.
    #[must_use]
    pub fn build(&self) -> (Vec<u8>, u32) {
        self.try_build()
            .expect("relocation build failed: use try_build() for fallible serialization")
    }

    /// Build the relocation table, with checked block and table sizes. Returns `(data, size)`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`RelocationTable::try_build`].
    pub fn try_build(&self) -> Result<(Vec<u8>, u32)> {
        let data = self.table.try_build()?;
        let size = u32::try_from(data.len())
            .map_err(|_| Error::invalid_data_directory("base-relocation table exceeds u32"))?;
        Ok((data, size))
    }

    /// Get the underlying table, normalized.
    #[must_use]
    pub fn into_table(self) -> RelocationTable {
        self.table.normalized()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relocation_entry_roundtrip() {
        let entry = RelocationEntry {
            reloc_type: RelocationType::HighLow,
            offset: 0x123,
        };
        let value = entry.to_u16();
        let parsed = RelocationEntry::from_u16(value);
        assert_eq!(entry.reloc_type, parsed.reloc_type);
        assert_eq!(entry.offset, parsed.offset);
    }

    #[test]
    fn test_relocation_entry_padding() {
        let entry = RelocationEntry::from_u16(0);
        assert!(entry.is_padding());

        let entry2 = RelocationEntry::from_u16(0x3123); // HIGHLOW
        assert!(!entry2.is_padding());
    }

    #[test]
    fn test_relocation_block_parse() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&0x1000u32.to_le_bytes()); // page_rva
        data[4..8].copy_from_slice(&16u32.to_le_bytes()); // block_size (header + 4 entries)
        data[8..10].copy_from_slice(&0x3010u16.to_le_bytes()); // HIGHLOW at 0x10
        data[10..12].copy_from_slice(&0x3020u16.to_le_bytes()); // HIGHLOW at 0x20
        data[12..14].copy_from_slice(&0x0000u16.to_le_bytes()); // padding
        data[14..16].copy_from_slice(&0xA030u16.to_le_bytes()); // DIR64 at 0x30

        let block = RelocationBlock::parse(&data).unwrap();
        assert_eq!(block.page_rva, 0x1000);
        assert_eq!(block.entries.len(), 4);
        assert_eq!(block.entries[0].reloc_type, RelocationType::HighLow);
        assert_eq!(block.entries[0].offset, 0x10);
        assert!(block.entries[2].is_padding());
        assert_eq!(block.entries[3].reloc_type, RelocationType::Dir64);
    }

    #[test]
    fn test_relocation_table_builder() {
        let mut table = RelocationTable::default();

        // Add relocations on different pages.
        table.add_highlow(0x1010);
        table.add_highlow(0x1020);
        table.add_dir64(0x2008);
        table.add_highlow(0x1030); // Same page as first two

        let data = table.build();

        // Parse the data again.
        let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
            let offset = rva as usize;
            if offset >= data.len() {
                return None;
            }
            let available = (data.len() - offset).min(len);
            Some(data[offset..offset + available].to_vec())
        };

        let parsed =
            RelocationTable::parse(0, u32::try_from(data.len()).unwrap(), read_fn).unwrap();
        assert_eq!(parsed.blocks.len(), 2); // Two pages: 0x1000 and 0x2000
        assert_eq!(parsed.relocation_count(), 4);
    }

    #[test]
    fn test_relocation_builder() {
        let mut builder = RelocationBuilder::new();

        builder
            .add_dir64(0x1000)
            .add_dir64(0x1008)
            .add_highlow(0x2000);

        assert_eq!(builder.relocation_count(), 3);

        let (data, size) = builder.build();
        assert!(size > 0);
        assert_eq!(data.len(), size as usize);

        // Parse the data again.
        let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
            let offset = rva as usize;
            if offset >= data.len() {
                return None;
            }
            let available = (data.len() - offset).min(len);
            Some(data[offset..offset + available].to_vec())
        };

        let parsed = RelocationTable::parse(0, size, read_fn).unwrap();
        assert_eq!(parsed.blocks.len(), 2);
        assert_eq!(parsed.relocation_count(), 3);
    }

    #[test]
    fn test_apply_wraps_at_field_width() {
        let entry = |reloc_type, offset| RelocationEntry { reloc_type, offset };
        let table = RelocationTable {
            blocks: vec![RelocationBlock {
                page_rva: 0,
                block_size: 0,
                entries: vec![
                    entry(RelocationType::HighLow, 0x00),
                    entry(RelocationType::Dir64, 0x08),
                    entry(RelocationType::Low, 0x10),
                    entry(RelocationType::High, 0x12),
                    entry(RelocationType::HighAdj, 0x14),
                    // HIGHADJ adjustment word (low half of the target), 0x7FFF.
                    RelocationEntry::from_u16(0x7FFF),
                ],
            }],
        };
        let mut buffer = vec![0u8; 0x18];
        buffer[0x00..0x04].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        buffer[0x08..0x10].copy_from_slice(&u64::MAX.to_le_bytes());
        buffer[0x10..0x12].copy_from_slice(&0xFFFFu16.to_le_bytes());
        buffer[0x12..0x14].copy_from_slice(&0xFFFFu16.to_le_bytes());
        buffer[0x14..0x16].copy_from_slice(&0xFFFFu16.to_le_bytes());

        let applied = table.try_apply(&mut buffer, 0x1_0020, true).unwrap();
        assert_eq!(applied, 5);
        // 0xFFFF_FFF0 + 0x1_0020 wraps to 0x0001_0010.
        assert_eq!(buffer[0x00..0x04], 0x0001_0010u32.to_le_bytes());
        // u64::MAX + 0x1_0020 wraps to 0x1_001F.
        assert_eq!(buffer[0x08..0x10], 0x0001_001Fu64.to_le_bytes());
        // Low 16 bits of 0xFFFF + 0x1_0020.
        assert_eq!(buffer[0x10..0x12], 0x001Fu16.to_le_bytes());
        // High 16 bits of 0xFFFF_0000 + 0x1_0020 = 0x1_0000_0020.
        assert_eq!(buffer[0x12..0x14], 0x0000u16.to_le_bytes());
        // (0xFFFF_7FFF + 0x1_0020 + 0x8000) >> 16 = 0x1_0001, truncated.
        assert_eq!(buffer[0x14..0x16], 0x0001u16.to_le_bytes());

        // A negative delta wraps below zero.
        let mut buffer = 0x10u32.to_le_bytes().to_vec();
        let table = RelocationTable {
            blocks: vec![RelocationBlock {
                page_rva: 0,
                block_size: 0,
                entries: vec![entry(RelocationType::HighLow, 0)],
            }],
        };
        table.try_apply(&mut buffer, -0x20, false).unwrap();
        assert_eq!(buffer, 0xFFFF_FFF0u32.to_le_bytes());
    }

    #[test]
    fn test_block_parse_rejects_bad_sizes() {
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        // The block size is larger than the data.
        data[4..8].copy_from_slice(&16u32.to_le_bytes());
        let error = RelocationBlock::parse(&data).unwrap_err();
        assert!(matches!(
            error.kind(),
            crate::ErrorKind::BufferTooSmall { .. }
        ));
        // The block size is smaller than the header.
        data[4..8].copy_from_slice(&4u32.to_le_bytes());
        let error = RelocationBlock::parse(&data).unwrap_err();
        assert!(matches!(
            error.kind(),
            crate::ErrorKind::InvalidDataDirectory(_)
        ));
        let error = RelocationBlock::parse(&data[..7]).unwrap_err();
        assert!(matches!(
            error.kind(),
            crate::ErrorKind::BufferTooSmall { .. }
        ));
    }

    #[test]
    fn test_apply_rejects_bad_targets() {
        let table = |entries| RelocationTable {
            blocks: vec![RelocationBlock {
                page_rva: 0,
                block_size: 0,
                entries,
            }],
        };
        let entry = |reloc_type, offset| RelocationEntry { reloc_type, offset };
        // The 4-byte field at offset 2 ends past the 4-byte buffer.
        let mut buffer = vec![0u8; 4];
        let error = table(vec![entry(RelocationType::HighLow, 2)])
            .try_apply(&mut buffer, 1, false)
            .unwrap_err();
        assert!(matches!(error.kind(), crate::ErrorKind::InvalidRva(2)));
        assert_eq!(buffer, [0; 4]);
        // A HIGHADJ entry without its adjustment word.
        let error = table(vec![entry(RelocationType::HighAdj, 0)])
            .try_apply(&mut buffer, 1, false)
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            crate::ErrorKind::InvalidDataDirectory(_)
        ));
    }
}
