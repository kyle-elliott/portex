//! Import table parsing and building.
//!
//! This module has types to read and write PE import tables. These types are the import
//! descriptors, the thunks and the full import table.
//!
//! # Examples
//!
//! ## Listing imports from a PE file
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! let imports = pe.imports()?;
//! for dll in &imports.dlls {
//!     println!("DLL: {}", dll.name);
//!     for thunk in &dll.imports {
//!         match thunk {
//!             portex::ImportThunk::Name { hint, name } => {
//!                 println!("  {} (hint: {})", name, hint);
//!             }
//!             portex::ImportThunk::Ordinal(ordinal) => {
//!                 println!("  Ordinal #{}", ordinal);
//!             }
//!         }
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Adding new imports to a PE file
//!
//! ```no_run
//! use portex::{ImportTable, ImportThunk, PeImage};
//!
//! # let file_bytes: &[u8] = &[];
//! let mut pe = PeImage::parse(file_bytes)?;
//!
//! // Build a new import table.
//! let mut imports = ImportTable::default();
//! imports.add_dll("kernel32.dll", vec![
//!     ImportThunk::Name { hint: 0, name: "LoadLibraryA".to_string() },
//!     ImportThunk::Name { hint: 0, name: "GetProcAddress".to_string() },
//! ]);
//! imports.add_dll("user32.dll", vec![
//!     ImportThunk::Name { hint: 0, name: "MessageBoxA".to_string() },
//! ]);
//!
//! // Update the PE image with the new imports.
//! pe.update_imports(&imports, None)?;
//! let rebuilt = pe.try_build()?;
//! assert!(!rebuilt.is_empty());
//! # Ok::<(), portex::Error>(())
//! ```

mod parts;

pub(crate) use parts::{skip_to_even, split_parts};

use nostdio::{Cursor, Seek, Write, WriteLe};

use crate::prelude::*;
use crate::{Error, Result};

/// Maximum length of a DLL name or a function name in an import or export table.
/// This limit is larger than all valid Windows DLL names. It stops unbounded reads on
/// malformed PE files.
const MAX_NAME_LEN: usize = 4096;
const MAX_IMPORT_DESCRIPTORS: usize = 65_536;
const MAX_IMPORT_THUNKS: usize = 1_048_576;
/// `IMAGE_ORDINAL_FLAG32`: high bit of a PE32 thunk marks an import by ordinal.
const IMAGE_ORDINAL_FLAG32: u32 = 0x8000_0000;
/// `IMAGE_ORDINAL_FLAG64`: high bit of a PE32+ thunk marks an import by ordinal.
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

/// Import descriptor (`IMAGE_IMPORT_DESCRIPTOR`, 20 bytes).
///
/// One descriptor describes one imported DLL.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportDescriptor {
    /// RVA of the Import Lookup Table (ILT), also known as the Import Name Table (INT).
    pub original_first_thunk: u32,
    /// Time stamp. The value is 0 if the imports are not bound.
    pub time_date_stamp: u32,
    /// Forwarder chain index. The value is -1 if there are no forwarders.
    pub forwarder_chain: u32,
    /// RVA of the DLL name (a null-terminated string).
    pub name_rva: u32,
    /// RVA of the Import Address Table (IAT).
    pub first_thunk: u32,
}

impl ImportDescriptor {
    /// Size of the on-disk structure in bytes.
    pub const SIZE: usize = Self::SIZE_U32 as usize;
    /// [`Self::SIZE`] as a `u32`, for RVA arithmetic.
    const SIZE_U32: u32 = 20;

    /// Return `true` if this descriptor is the null terminator.
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.original_first_thunk == 0
            && self.time_date_stamp == 0
            && self.forwarder_chain == 0
            && self.name_rva == 0
            && self.first_thunk == 0
    }

    /// Parse a descriptor from bytes.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::BufferTooSmall` if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(data) = data.first_chunk::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };

        Ok(Self {
            original_first_thunk: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            time_date_stamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            forwarder_chain: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            name_rva: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            first_thunk: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
        })
    }

    /// Write the descriptor to a buffer.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::BufferTooSmall` if `buf` is shorter than [`Self::SIZE`].
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        let len = buf.len();
        let Some(buf) = buf.first_chunk_mut::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, len));
        };
        *buf = self.to_array();
        Ok(())
    }

    /// Serialize the descriptor to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_array().to_vec()
    }

    /// Return the fields as the on-disk structure.
    fn to_array(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.original_first_thunk.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..12].copy_from_slice(&self.forwarder_chain.to_le_bytes());
        buf[12..16].copy_from_slice(&self.name_rva.to_le_bytes());
        buf[16..20].copy_from_slice(&self.first_thunk.to_le_bytes());
        buf
    }
}

/// Import thunk entry. The entry is an import by ordinal or an import by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportThunk {
    /// Import by ordinal number.
    Ordinal(u16),
    /// Import by name, with a hint.
    Name {
        /// Index into the export name pointer table of the exporting DLL. The loader tries
        /// this index first when it resolves the name.
        hint: u16,
        /// Imported function name.
        name: String,
    },
}

impl ImportThunk {
    /// Return `true` if a PE32 thunk value is an import by ordinal (high bit set).
    #[must_use]
    pub fn is_ordinal_entry_32(value: u32) -> bool {
        value & IMAGE_ORDINAL_FLAG32 != 0
    }

    /// Return `true` if a PE32+ thunk value is an import by ordinal (high bit set).
    #[must_use]
    pub fn is_ordinal_entry_64(value: u64) -> bool {
        value & IMAGE_ORDINAL_FLAG64 != 0
    }

    /// Get the ordinal from a PE32 thunk value.
    #[must_use]
    pub fn ordinal_from_32(value: u32) -> u16 {
        let [low, high, ..] = value.to_le_bytes();
        u16::from_le_bytes([low, high])
    }

    /// Get the ordinal from a PE32+ thunk value.
    #[must_use]
    pub fn ordinal_from_64(value: u64) -> u16 {
        let [low, high, ..] = value.to_le_bytes();
        u16::from_le_bytes([low, high])
    }

    /// Get the RVA of the hint/name entry from a PE32 thunk value.
    #[must_use]
    pub fn hint_name_rva_from_32(value: u32) -> u32 {
        value & 0x7FFF_FFFF
    }

    /// Get the RVA of the hint/name entry from a PE32+ thunk value.
    #[must_use]
    pub fn hint_name_rva_from_64(value: u64) -> u32 {
        let [b0, b1, b2, b3, ..] = value.to_le_bytes();
        u32::from_le_bytes([b0, b1, b2, b3]) & 0x7FFF_FFFF
    }
}

/// One imported DLL with its imports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedDll {
    /// The DLL name.
    pub name: String,
    /// Import descriptor.
    pub descriptor: ImportDescriptor,
    /// Imported functions.
    pub imports: Vec<ImportThunk>,
}

/// A full import table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportTable {
    /// Imported DLLs.
    pub dlls: Vec<ImportedDll>,
}

impl ImportTable {
    /// Parse an import table from a PE file.
    ///
    /// `import_rva` is the RVA from the import data directory. `read_at_rva` is a closure
    /// that reads bytes at an RVA.
    ///
    /// # Errors
    ///
    /// Returns an error if one of these conditions occurs:
    ///
    /// - A descriptor, a thunk or a name cannot be read.
    /// - A non-null descriptor has no DLL name.
    /// - An ordinal thunk has reserved bits set.
    /// - A named thunk has a null or out-of-range hint/name RVA.
    /// - An RVA computation overflows.
    /// - The descriptor table or a thunk table has no null terminator.
    pub fn parse<F>(import_rva: u32, is_64bit: bool, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        Self::parse_bounded(import_rva, None, is_64bit, read_at_rva)
    }

    /// Parse an import descriptor table, and do not read descriptors past its
    /// data directory size.
    ///
    /// Names and thunk arrays can be in other parts of the image. The PE format
    /// permits this.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::parse`]. Also returns an error if
    /// `import_size` is smaller than one descriptor, or if the descriptor table
    /// has no terminator in the first `import_size` bytes.
    pub fn parse_sized<F>(
        import_rva: u32,
        import_size: u32,
        is_64bit: bool,
        read_at_rva: F,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        if import_size < ImportDescriptor::SIZE_U32 {
            return Err(Error::invalid_data_directory(format!(
                "import directory is {import_size} bytes, expected at least {}",
                ImportDescriptor::SIZE
            )));
        }
        Self::parse_bounded(import_rva, Some(import_size), is_64bit, read_at_rva)
    }

    fn parse_bounded<F>(
        import_rva: u32,
        import_size: Option<u32>,
        is_64bit: bool,
        read_at_rva: F,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut dlls = Vec::new();
        let mut offset = 0u32;

        for _ in 0..MAX_IMPORT_DESCRIPTORS {
            if let Some(size) = import_size {
                let end = offset
                    .checked_add(ImportDescriptor::SIZE_U32)
                    .ok_or_else(|| {
                        Error::invalid_data_directory("import descriptor range overflow")
                    })?;
                if end > size {
                    return Err(Error::invalid_data_directory(
                        "import descriptor table is missing a terminator within its directory",
                    ));
                }
            }
            // Read the import descriptor.
            let descriptor_rva = import_rva
                .checked_add(offset)
                .ok_or_else(|| Error::invalid_data_directory("import descriptor RVA overflow"))?;
            let desc_data = read_at_rva(descriptor_rva, ImportDescriptor::SIZE)
                .ok_or(Error::invalid_rva(descriptor_rva))?;
            let descriptor = ImportDescriptor::parse(&desc_data)?;

            if descriptor.is_null() {
                return Ok(Self { dlls });
            }
            if descriptor.name_rva == 0 {
                return Err(Error::invalid_data_directory(
                    "non-null import descriptor has no DLL name RVA",
                ));
            }

            // Read the DLL name.
            let name = Self::read_string(&read_at_rva, descriptor.name_rva)?;

            // Read the thunks.
            let thunk_rva = if descriptor.original_first_thunk != 0 {
                descriptor.original_first_thunk
            } else {
                descriptor.first_thunk
            };

            let imports = Self::read_thunks(&read_at_rva, thunk_rva, is_64bit)?;

            dlls.push(ImportedDll {
                name,
                descriptor,
                imports,
            });

            offset = offset
                .checked_add(ImportDescriptor::SIZE_U32)
                .ok_or_else(|| {
                    Error::invalid_data_directory("import descriptor table size overflow")
                })?;
        }

        Err(Error::invalid_data_directory(
            "import descriptor table is missing a terminator",
        ))
    }

    fn read_string<F>(read_at_rva: &F, rva: u32) -> Result<String>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        crate::parse_utils::read_c_string(read_at_rva, rva, MAX_NAME_LEN, "import name")
    }

    fn read_thunks<F>(read_at_rva: &F, thunk_rva: u32, is_64bit: bool) -> Result<Vec<ImportThunk>>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut imports = Vec::new();
        let thunk_size: u8 = if is_64bit { 8 } else { 4 };
        let mut offset = 0u32;

        for _ in 0..MAX_IMPORT_THUNKS {
            let entry_rva = thunk_rva
                .checked_add(offset)
                .ok_or_else(|| Error::invalid_data_directory("import thunk RVA overflow"))?;
            let data = crate::parse_utils::read_exact_rva(
                read_at_rva,
                entry_rva,
                usize::from(thunk_size),
                "import thunk",
            )?;

            let (is_ordinal, ordinal, hint_rva) = if is_64bit {
                let bytes = data
                    .first_chunk::<8>()
                    .ok_or_else(|| Error::buffer_too_small(8, data.len()))?;
                let value = u64::from_le_bytes(*bytes);
                if value == 0 {
                    return Ok(imports);
                }
                if ImportThunk::is_ordinal_entry_64(value) {
                    if value & 0x7fff_ffff_ffff_0000 != 0 {
                        return Err(Error::invalid_data_directory(
                            "64-bit ordinal import has nonzero reserved bits",
                        ));
                    }
                    (true, ImportThunk::ordinal_from_64(value), 0)
                } else {
                    let hint_rva = u32::try_from(value).map_err(|_| {
                        Error::invalid_data_directory(
                            "64-bit import hint/name address does not fit an RVA",
                        )
                    })?;
                    (false, 0, hint_rva)
                }
            } else {
                let bytes = data
                    .first_chunk::<4>()
                    .ok_or_else(|| Error::buffer_too_small(4, data.len()))?;
                let value = u32::from_le_bytes(*bytes);
                if value == 0 {
                    return Ok(imports);
                }
                if ImportThunk::is_ordinal_entry_32(value) {
                    if value & 0x7fff_0000 != 0 {
                        return Err(Error::invalid_data_directory(
                            "32-bit ordinal import has nonzero reserved bits",
                        ));
                    }
                    (true, ImportThunk::ordinal_from_32(value), 0)
                } else {
                    (false, 0, ImportThunk::hint_name_rva_from_32(value))
                }
            };

            let thunk = if is_ordinal {
                ImportThunk::Ordinal(ordinal)
            } else {
                if hint_rva == 0 {
                    return Err(Error::invalid_data_directory(
                        "named import has a null hint/name RVA",
                    ));
                }
                // Read the hint (2 bytes) and the name.
                let hint_data =
                    crate::parse_utils::read_exact_rva(read_at_rva, hint_rva, 2, "import hint")?;
                let hint_bytes = hint_data
                    .first_chunk::<2>()
                    .ok_or_else(|| Error::buffer_too_small(2, hint_data.len()))?;
                let hint = u16::from_le_bytes(*hint_bytes);
                let name_rva = hint_rva.checked_add(2).ok_or_else(|| {
                    Error::invalid_data_directory("import hint/name RVA overflow")
                })?;
                let name = Self::read_string(read_at_rva, name_rva)?;
                ImportThunk::Name { hint, name }
            };

            imports.push(thunk);
            offset = offset
                .checked_add(u32::from(thunk_size))
                .ok_or_else(|| Error::invalid_data_directory("import thunk table size overflow"))?;
        }

        Err(Error::invalid_data_directory(
            "import thunk table is missing a terminator",
        ))
    }

    /// Return `true` if the import table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.dlls.is_empty()
    }

    /// Find a DLL by name (case-insensitive).
    #[must_use]
    pub fn find_dll(&self, name: &str) -> Option<&ImportedDll> {
        self.dlls
            .iter()
            .find(|dll| dll.name.eq_ignore_ascii_case(name))
    }

    /// Get the total number of imported functions.
    #[must_use]
    pub fn import_count(&self) -> usize {
        self.dlls.iter().map(|dll| dll.imports.len()).sum()
    }

    /// Add a new DLL with its imports.
    pub fn add_dll(&mut self, name: &str, imports: Vec<ImportThunk>) {
        self.dlls.push(ImportedDll {
            name: name.to_string(),
            descriptor: ImportDescriptor::default(),
            imports,
        });
    }

    /// Add an import to an existing DLL. If the DLL does not exist, add the DLL.
    pub fn add_import(&mut self, dll_name: &str, import: ImportThunk) {
        if let Some(dll) = self
            .dlls
            .iter_mut()
            .find(|d| d.name.eq_ignore_ascii_case(dll_name))
        {
            dll.imports.push(import);
        } else {
            self.add_dll(dll_name, vec![import]);
        }
    }

    /// Add an import by name.
    pub fn add_named_import(&mut self, dll_name: &str, func_name: &str, hint: u16) {
        self.add_import(
            dll_name,
            ImportThunk::Name {
                hint,
                name: func_name.to_string(),
            },
        );
    }

    /// Add an import by ordinal.
    pub fn add_ordinal_import(&mut self, dll_name: &str, ordinal: u16) {
        self.add_import(dll_name, ImportThunk::Ordinal(ordinal));
    }
}

/// Builder that serializes an import table to section data.
#[derive(Debug)]
pub struct ImportTableBuilder {
    /// If `true`, build for PE32+. If `false`, build for PE32.
    pub is_64bit: bool,
    /// RVA of the start of the built import data.
    pub base_rva: u32,
}

impl ImportTableBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new(is_64bit: bool, base_rva: u32) -> Self {
        Self { is_64bit, base_rva }
    }

    /// Calculate the total size of the import section.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_calculate_size`] fails.
    #[must_use]
    pub fn calculate_size(&self, table: &ImportTable) -> usize {
        self.try_calculate_size(table)
            .expect("import table size overflow: use try_calculate_size()")
    }

    /// Calculate the serialized size. Use checked arithmetic and validate the
    /// names.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data-directory error if a DLL name or a function name
    /// is empty or contains NUL. Also returns this error if a size computation
    /// overflows `usize`.
    pub fn try_calculate_size(&self, table: &ImportTable) -> Result<usize> {
        if table.dlls.is_empty() {
            return Ok(0);
        }
        Ok(self.layout(table)?.total_size)
    }

    /// Validate the names in `table` and calculate the layout of the built
    /// table. Do not call this function for an empty table.
    fn layout(&self, table: &ImportTable) -> Result<ImportLayout> {
        let thunk_size = self.thunk_size();

        // Import descriptors: one for each DLL, plus a null terminator.
        let descriptors_size = table
            .dlls
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(ImportDescriptor::SIZE))
            .ok_or_else(|| Error::invalid_data_directory("import descriptor size overflow"))?;

        // ILT and IAT. Each has the thunks of each DLL plus a null terminator for each DLL.
        let mut thunks_count = 0usize;
        for dll in &table.dlls {
            if dll.name.is_empty() || dll.name.as_bytes().contains(&0) {
                return Err(Error::invalid_data_directory(
                    "import DLL names must be nonempty and contain no NUL bytes",
                ));
            }
            thunks_count =
                thunks_count
                    .checked_add(dll.imports.len().checked_add(1).ok_or_else(|| {
                        Error::invalid_data_directory("import thunk count overflow")
                    })?)
                    .ok_or_else(|| Error::invalid_data_directory("import thunk count overflow"))?;
        }
        // The IAT is the same size as the ILT.
        let thunk_table_size = thunks_count
            .checked_mul(thunk_size)
            .ok_or_else(|| Error::invalid_data_directory("import thunk table size overflow"))?;

        // Hint/name entries.
        let mut hint_names_size = 0usize;
        for dll in &table.dlls {
            for import in &dll.imports {
                if let ImportThunk::Name { name, .. } = import {
                    if name.is_empty() || name.as_bytes().contains(&0) {
                        return Err(Error::invalid_data_directory(
                            "import names must be nonempty and contain no NUL bytes",
                        ));
                    }
                    // Each entry: 2-byte hint, name, null terminator, padding to an even size.
                    let entry_size = name.len().checked_add(3).ok_or_else(|| {
                        Error::invalid_data_directory("import name size overflow")
                    })?;
                    let aligned = entry_size.checked_add(1).ok_or_else(|| {
                        Error::invalid_data_directory("import name alignment overflow")
                    })? & !1;
                    hint_names_size = hint_names_size.checked_add(aligned).ok_or_else(|| {
                        Error::invalid_data_directory("import names size overflow")
                    })?;
                }
            }
        }

        // DLL names.
        let mut dll_names_size = 0usize;
        for dll in &table.dlls {
            dll_names_size = dll_names_size
                .checked_add(dll.name.len().checked_add(1).ok_or_else(|| {
                    Error::invalid_data_directory("import DLL name size overflow")
                })?)
                .ok_or_else(|| Error::invalid_data_directory("import DLL names size overflow"))?;
        }

        let overflow = || Error::invalid_data_directory("import table size overflow");
        let iat_offset = descriptors_size
            .checked_add(thunk_table_size) // ILT
            .ok_or_else(overflow)?;
        let hint_names_offset = iat_offset
            .checked_add(thunk_table_size) // IAT
            .ok_or_else(overflow)?;
        let dll_names_offset = hint_names_offset
            .checked_add(hint_names_size)
            .ok_or_else(overflow)?;
        let total_size = dll_names_offset
            .checked_add(dll_names_size)
            .ok_or_else(overflow)?;
        Ok(ImportLayout {
            descriptors_size,
            thunk_table_size,
            iat_offset,
            hint_names_offset,
            dll_names_offset,
            total_size,
        })
    }

    /// Build the import section data and return `(section_data, iat_rva, iat_size)`.
    ///
    /// Use the IAT RVA and size to update the IAT data directory.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] fails.
    #[must_use]
    pub fn build(&self, table: &ImportTable) -> (Vec<u8>, u32, u32) {
        self.try_build(table)
            .expect("import table build failed: use try_build() for fallible serialization")
    }

    /// Build the import table with checked offsets and sizes.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::try_calculate_size`]. Also returns an
    /// invalid-data-directory error if one of these conditions occurs:
    ///
    /// - The table is larger than `u32`.
    /// - The RVA range of the table overflows.
    /// - For PE32, an RVA reaches the ordinal flag bit.
    pub fn try_build(&self, table: &ImportTable) -> Result<(Vec<u8>, u32, u32)> {
        if table.dlls.is_empty() {
            return Ok((Vec::new(), 0, 0));
        }
        let layout = self.layout(table)?;
        let size = u32::try_from(layout.total_size)
            .map_err(|_| Error::invalid_data_directory("import table exceeds u32"))?;
        let end = self
            .base_rva
            .checked_add(size)
            .ok_or_else(|| Error::invalid_data_directory("import table RVA range overflow"))?;
        if !self.is_64bit && end > IMAGE_ORDINAL_FLAG32 {
            return Err(Error::invalid_data_directory(
                "PE32 import hint/name RVAs would overlap the ordinal flag",
            ));
        }
        self.write_table(table, &layout)
    }

    /// Serialize `table` into a new buffer with the parts at the offsets in
    /// `layout`.
    fn write_table(
        &self,
        table: &ImportTable,
        layout: &ImportLayout,
    ) -> Result<(Vec<u8>, u32, u32)> {
        let thunk_skip = self.thunk_skip();
        let mut data = vec![0u8; layout.total_size];

        // The parts are in this order: descriptors, ILT, IAT, hint/name
        // entries, DLL names. The ILT starts after the descriptors.
        let starts = [
            0,
            layout.descriptors_size,
            layout.iat_offset,
            layout.hint_names_offset,
            layout.dll_names_offset,
        ];
        let [_, lookup_start, iat_start, hint_name_start, dll_name_start] = starts;
        let [mut desc, mut lookup, mut iat, mut hint_name, mut dll_name] =
            split_parts(&mut data, starts)?;

        for dll in &table.dlls {
            // Write the DLL name. The zeroed buffer supplies the null terminator.
            let dll_name_rva = self.rva_at(dll_name_start, dll_name.position())?;
            dll_name.write_all(dll.name.as_bytes())?;
            dll_name.seek_relative(1)?;

            // Write the thunks (ILT and IAT).
            let lookup_table_rva = self.rva_at(lookup_start, lookup.position())?;
            let first_thunk_rva = self.rva_at(iat_start, iat.position())?;

            for import in &dll.imports {
                let (by_ordinal, thunk_value) = match import {
                    ImportThunk::Ordinal(ord) => (true, u32::from(*ord)),
                    ImportThunk::Name { hint, name } => {
                        // Write the hint/name entry: hint, name, null terminator,
                        // and padding to an even offset in the part.
                        let hint_name_rva = self.rva_at(hint_name_start, hint_name.position())?;
                        hint_name.write_u16_le(*hint)?;
                        hint_name.write_all(name.as_bytes())?;
                        hint_name.seek_relative(1)?;
                        skip_to_even(&mut hint_name)?;

                        (false, hint_name_rva)
                    }
                };

                // The IAT holds the same thunks as the ILT until the loader binds it.
                self.write_thunk(&mut lookup, by_ordinal, thunk_value)?;
                self.write_thunk(&mut iat, by_ordinal, thunk_value)?;
            }

            // Skip the null terminator of each thunk table.
            lookup.seek_relative(thunk_skip)?;
            iat.seek_relative(thunk_skip)?;

            // Write the import descriptor.
            let descriptor = ImportDescriptor {
                original_first_thunk: lookup_table_rva,
                time_date_stamp: 0,
                forwarder_chain: 0,
                name_rva: dll_name_rva,
                first_thunk: first_thunk_rva,
            };
            desc.write_all(&descriptor.to_array())?;
        }

        // The null terminator descriptor is already zero.

        let iat_rva = self.rva_at(layout.iat_offset, 0)?;
        let iat_size = u32::try_from(layout.thunk_table_size)
            .map_err(|_| Error::invalid_data_directory("import address table exceeds u32"))?;
        Ok((data, iat_rva, iat_size))
    }

    /// Size of one ILT/IAT thunk: 8 bytes for PE32+, 4 bytes for PE32.
    fn thunk_size(&self) -> usize {
        if self.is_64bit { 8 } else { 4 }
    }

    /// Return the size of one ILT/IAT thunk as a cursor offset.
    fn thunk_skip(&self) -> i64 {
        if self.is_64bit { 8 } else { 4 }
    }

    /// Return the RVA of byte `position` in the part that starts at byte `start` of the built
    /// import data.
    fn rva_at(&self, start: usize, position: u64) -> Result<u32> {
        u32::try_from(start)
            .ok()
            .zip(u32::try_from(position).ok())
            .and_then(|(start, position)| start.checked_add(position))
            .and_then(|offset| self.base_rva.checked_add(offset))
            .ok_or_else(|| Error::invalid_data_directory("import table RVA overflow"))
    }

    /// Write one ILT/IAT thunk at `cursor`: an ordinal (with the ordinal flag
    /// set) or a hint/name RVA, sized for PE32 or PE32+.
    fn write_thunk(
        &self,
        cursor: &mut Cursor<&mut [u8]>,
        by_ordinal: bool,
        value: u32,
    ) -> Result<()> {
        if self.is_64bit {
            let flag = if by_ordinal { IMAGE_ORDINAL_FLAG64 } else { 0 };
            cursor.write_u64_le(flag | u64::from(value))?;
        } else {
            let flag = if by_ordinal { IMAGE_ORDINAL_FLAG32 } else { 0 };
            cursor.write_u32_le(flag | value)?;
        }
        Ok(())
    }
}

/// Offsets and sizes of the parts of a built import table.
///
/// The parts are in this order: descriptors, ILT, IAT, hint/name entries,
/// DLL names. The ILT starts at `descriptors_size`.
struct ImportLayout {
    /// Size of the descriptor array, with its null terminator.
    descriptors_size: usize,
    /// Size of one thunk table. The ILT and the IAT have the same size.
    thunk_table_size: usize,
    /// Offset of the IAT in the built buffer.
    iat_offset: usize,
    /// Offset of the first hint/name entry in the built buffer.
    hint_names_offset: usize,
    /// Offset of the first DLL name in the built buffer.
    dll_names_offset: usize,
    /// Size of the full table.
    total_size: usize,
}

#[cfg(test)]
mod tests;
