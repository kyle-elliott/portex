//! Export table parsing and building.
//!
//! This module reads and writes PE export tables. An export table holds the export directory
//! (`IMAGE_EXPORT_DIRECTORY`) and the exported functions.
//!
//! # Examples
//!
//! ## Listing exports from a DLL
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! let exports = pe.exports()?;
//! println!("DLL name: {}", exports.dll_name);
//! println!("Ordinal base: {}", exports.directory.base);
//!
//! for func in &exports.exports {
//!     let name = func.name.as_deref().unwrap_or("<unnamed>");
//!     let addr = match &func.address {
//!         portex::ExportAddress::Rva(rva) => format!("{:#x}", rva),
//!         portex::ExportAddress::Forwarder(s) => s.clone(),
//!     };
//!     println!("  {} (ordinal {}): {}", name, func.ordinal, addr);
//! }
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Creating a DLL with exports
//!
//! ```no_run
//! use portex::{ExportTable, PeImage};
//!
//! # let file_bytes: &[u8] = &[];
//! let mut pe = PeImage::parse(file_bytes)?;
//!
//! // Build the export table.
//! let mut exports = ExportTable::default();
//! exports.dll_name = "mylib.dll".to_string();
//! exports.directory.base = 1;
//! exports.add_export(Some("MyFunction1"), 0x1000);
//! exports.add_export(Some("MyFunction2"), 0x2000);
//! exports.add_export(None, 0x3000); // No name, only an ordinal.
//!
//! // Put the new exports into the PE image.
//! pe.update_exports(&exports, None)?;
//! let rebuilt = pe.try_build()?;
//! assert!(!rebuilt.is_empty());
//! # Ok::<(), portex::Error>(())
//! ```

use crate::prelude::*;
use crate::{Error, Result};

/// The maximum length of a DLL name or a function name in an export table.
///
/// This limit covers all valid Windows symbol names. It also stops unbounded reads on malformed
/// PE files.
const MAX_NAME_LEN: usize = 4096;
const MAX_EXPORT_FUNCTIONS: u32 = 1_048_576;

/// `IMAGE_EXPORT_DIRECTORY`: the 40-byte header of the export data directory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportDirectory {
    /// Export flags. Reserved, must be 0.
    pub characteristics: u32,
    /// The time and date stamp.
    pub time_date_stamp: u32,
    /// The major version.
    pub major_version: u16,
    /// The minor version.
    pub minor_version: u16,
    /// The RVA of the DLL name.
    pub name_rva: u32,
    /// The first ordinal number.
    pub base: u32,
    /// The number of entries in the export address table (EAT).
    pub number_of_functions: u32,
    /// The number of entries in the name pointer table.
    pub number_of_names: u32,
    /// The RVA of the export address table (EAT).
    pub address_of_functions: u32,
    /// The RVA of the export name pointer table.
    pub address_of_names: u32,
    /// The RVA of the export ordinal table.
    pub address_of_name_ordinals: u32,
}

impl ExportDirectory {
    /// Size of a serialized `IMAGE_EXPORT_DIRECTORY` in bytes.
    pub const SIZE: usize = 40;

    /// Parse an export directory from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::buffer_too_small`] if `data` is shorter than
    /// [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(d) = data.first_chunk::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };

        Ok(Self {
            characteristics: u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
            time_date_stamp: u32::from_le_bytes([d[4], d[5], d[6], d[7]]),
            major_version: u16::from_le_bytes([d[8], d[9]]),
            minor_version: u16::from_le_bytes([d[10], d[11]]),
            name_rva: u32::from_le_bytes([d[12], d[13], d[14], d[15]]),
            base: u32::from_le_bytes([d[16], d[17], d[18], d[19]]),
            number_of_functions: u32::from_le_bytes([d[20], d[21], d[22], d[23]]),
            number_of_names: u32::from_le_bytes([d[24], d[25], d[26], d[27]]),
            address_of_functions: u32::from_le_bytes([d[28], d[29], d[30], d[31]]),
            address_of_names: u32::from_le_bytes([d[32], d[33], d[34], d[35]]),
            address_of_name_ordinals: u32::from_le_bytes([d[36], d[37], d[38], d[39]]),
        })
    }

    /// Write the export directory to a buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::buffer_too_small`] if `buf` is shorter than
    /// [`Self::SIZE`].
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        let buf_len = buf.len();
        let Some(out) = buf.first_chunk_mut::<{ ExportDirectory::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, buf_len));
        };
        self.encode(out);
        Ok(())
    }

    /// Serialize the export directory to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = [0u8; ExportDirectory::SIZE];
        self.encode(&mut buf);
        buf.to_vec()
    }

    fn encode(&self, buf: &mut [u8; ExportDirectory::SIZE]) {
        buf[0..4].copy_from_slice(&self.characteristics.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..10].copy_from_slice(&self.major_version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.minor_version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.name_rva.to_le_bytes());
        buf[16..20].copy_from_slice(&self.base.to_le_bytes());
        buf[20..24].copy_from_slice(&self.number_of_functions.to_le_bytes());
        buf[24..28].copy_from_slice(&self.number_of_names.to_le_bytes());
        buf[28..32].copy_from_slice(&self.address_of_functions.to_le_bytes());
        buf[32..36].copy_from_slice(&self.address_of_names.to_le_bytes());
        buf[36..40].copy_from_slice(&self.address_of_name_ordinals.to_le_bytes());
    }
}

/// One exported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedFunction {
    /// The ordinal number.
    pub ordinal: u32,
    /// The function name, if the function is exported by name.
    pub name: Option<String>,
    /// More names that resolve to the same ordinal and EAT slot.
    pub aliases: Vec<String>,
    /// The RVA of the function, or the forwarder name.
    pub address: ExportAddress,
}

/// The address of an exported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportAddress {
    /// The RVA of the function.
    Rva(u32),
    /// A forwarder to a function in another DLL (for example "NTDLL.RtlAllocateHeap").
    Forwarder(String),
}

/// The complete export table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportTable {
    /// The export directory header.
    pub directory: ExportDirectory,
    /// The DLL name.
    pub dll_name: String,
    /// The exported functions.
    pub exports: Vec<ExportedFunction>,
}

impl ExportTable {
    /// Parse an export table from a PE file.
    ///
    /// - `export_rva` is the RVA from the data directory.
    /// - `export_size` is the size from the data directory. The parser uses it to find forwarders.
    /// - `read_at_rva` is a closure that reads bytes at an RVA.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - `export_size` is smaller than `IMAGE_EXPORT_DIRECTORY`.
    /// - The parser cannot read the directory, a table, a name or a forwarder string.
    /// - The function count is more than the safety limit, or less than the name count.
    /// - A table is outside the export directory range.
    /// - An RVA or an ordinal overflows.
    /// - A name refers to an empty slot in the address table.
    pub fn parse<F>(export_rva: u32, export_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        if (export_size as usize) < ExportDirectory::SIZE {
            return Err(Error::invalid_data_directory(format!(
                "export directory is {} bytes, expected at least {}",
                export_size,
                ExportDirectory::SIZE
            )));
        }
        // Read the export directory.
        let dir_data =
            read_at_rva(export_rva, ExportDirectory::SIZE).ok_or(Error::invalid_rva(export_rva))?;
        let directory = ExportDirectory::parse(&dir_data)?;

        if directory.number_of_functions > MAX_EXPORT_FUNCTIONS {
            return Err(Error::invalid_data_directory(format!(
                "export function count {} exceeds the safety limit {}",
                directory.number_of_functions, MAX_EXPORT_FUNCTIONS
            )));
        }
        if directory.name_rva == 0 {
            return Err(Error::invalid_data_directory(
                "export directory has a null DLL name RVA",
            ));
        }

        // Read the DLL name.
        let dll_name = Self::read_string(
            &read_at_rva,
            directory.name_rva,
            export_rva,
            export_size,
            "export DLL name",
        )?;

        // Read the exports.
        let exports = Self::read_exports(&read_at_rva, &directory, export_rva, export_size)?;

        Ok(Self {
            directory,
            dll_name,
            exports,
        })
    }

    fn read_string<F>(
        read_at_rva: &F,
        rva: u32,
        export_rva: u32,
        export_size: u32,
        context: &str,
    ) -> Result<String>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        crate::parse_utils::read_c_string_in_range(
            read_at_rva,
            rva,
            export_rva,
            export_size,
            MAX_NAME_LEN,
            context,
        )
    }

    fn read_exports<F>(
        read_at_rva: &F,
        dir: &ExportDirectory,
        export_rva: u32,
        export_size: u32,
    ) -> Result<Vec<ExportedFunction>>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let export_end = export_rva
            .checked_add(export_size)
            .ok_or_else(|| Error::invalid_data_directory("export directory RVA overflow"))?;
        Self::validate_tables(dir, export_rva, export_size)?;
        let mut exports =
            Self::read_address_table(read_at_rva, dir, export_rva, export_size, export_end)?;
        for index in 0..dir.number_of_names {
            Self::read_name_entry(
                read_at_rva,
                dir,
                index,
                export_rva,
                export_size,
                &mut exports,
            )?;
        }
        Ok(exports)
    }

    /// Check that the address table, the name pointer table and the ordinal table are all in
    /// the export directory range.
    ///
    /// The name count can be more than the function count, because many names (aliases) can
    /// refer to one function.
    fn validate_tables(dir: &ExportDirectory, export_rva: u32, export_size: u32) -> Result<()> {
        crate::parse_utils::bounded_table_range(
            dir.address_of_functions,
            dir.number_of_functions,
            4,
            export_rva,
            export_size,
            "export address table",
        )?;
        crate::parse_utils::bounded_table_range(
            dir.address_of_names,
            dir.number_of_names,
            4,
            export_rva,
            export_size,
            "export name-pointer table",
        )?;
        crate::parse_utils::bounded_table_range(
            dir.address_of_name_ordinals,
            dir.number_of_names,
            2,
            export_rva,
            export_size,
            "export ordinal table",
        )?;
        Ok(())
    }

    /// Read the export address table (EAT).
    ///
    /// The function skips empty slots. An entry that points into the export directory is a
    /// forwarder.
    fn read_address_table<F>(
        read_at_rva: &F,
        dir: &ExportDirectory,
        export_rva: u32,
        export_size: u32,
        export_end: u32,
    ) -> Result<Vec<ExportedFunction>>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut exports = Vec::new();
        for i in 0..dir.number_of_functions {
            let addr_rva = dir
                .address_of_functions
                .checked_add(i.checked_mul(4).ok_or_else(|| {
                    Error::invalid_data_directory("export address-table offset overflow")
                })?)
                .ok_or_else(|| {
                    Error::invalid_data_directory("export address-table RVA overflow")
                })?;
            let func_rva = u32::from_le_bytes(read_array_rva(
                read_at_rva,
                addr_rva,
                "export address entry",
            )?);

            if func_rva == 0 {
                continue; // Empty slot.
            }

            let ordinal = dir
                .base
                .checked_add(i)
                .ok_or_else(|| Error::invalid_data_directory("export ordinal overflow"))?;

            // An RVA in the export directory range is a forwarder.
            let address = if func_rva >= export_rva && func_rva < export_end {
                let fwd_name = Self::read_string(
                    read_at_rva,
                    func_rva,
                    export_rva,
                    export_size,
                    "export forwarder",
                )?;
                ExportAddress::Forwarder(fwd_name)
            } else {
                ExportAddress::Rva(func_rva)
            };

            exports.push(ExportedFunction {
                ordinal,
                name: None,
                aliases: Vec::new(),
                address,
            });
        }
        Ok(exports)
    }

    /// Read entry `index` of the name pointer table and the ordinal table.
    ///
    /// The function attaches the name to the export that the entry refers to. If that export
    /// already has a name, the function adds the name as an alias.
    fn read_name_entry<F>(
        read_at_rva: &F,
        dir: &ExportDirectory,
        index: u32,
        export_rva: u32,
        export_size: u32,
        exports: &mut [ExportedFunction],
    ) -> Result<()>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        // Read the name RVA.
        let name_ptr_rva = dir
            .address_of_names
            .checked_add(index.checked_mul(4).ok_or_else(|| {
                Error::invalid_data_directory("export name-table offset overflow")
            })?)
            .ok_or_else(|| Error::invalid_data_directory("export name-table RVA overflow"))?;
        let name_rva = u32::from_le_bytes(read_array_rva(
            read_at_rva,
            name_ptr_rva,
            "export name pointer",
        )?);

        // Read the ordinal index.
        let ord_rva = dir
            .address_of_name_ordinals
            .checked_add(index.checked_mul(2).ok_or_else(|| {
                Error::invalid_data_directory("export ordinal-table offset overflow")
            })?)
            .ok_or_else(|| Error::invalid_data_directory("export ordinal-table RVA overflow"))?;
        let ord_index = u16::from_le_bytes(read_array_rva(read_at_rva, ord_rva, "export ordinal")?);

        // Read the name.
        let name = Self::read_string(
            read_at_rva,
            name_rva,
            export_rva,
            export_size,
            "export function name",
        )?;

        // Find the export that has this ordinal.
        let ordinal = dir
            .base
            .checked_add(u32::from(ord_index))
            .ok_or_else(|| Error::invalid_data_directory("export ordinal overflow"))?;
        let export = exports
            .iter_mut()
            .find(|export| export.ordinal == ordinal)
            .ok_or_else(|| {
                Error::invalid_data_directory(format!(
                    "export name references empty function slot {ord_index}"
                ))
            })?;
        if export.name.is_none() {
            export.name = Some(name);
        } else {
            export.aliases.push(name);
        }
        Ok(())
    }

    /// Return `true` if the export table has no exports.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exports.is_empty()
    }

    /// Find an export by name or by alias.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&ExportedFunction> {
        self.exports.iter().find(|export| {
            export.name.as_deref() == Some(name) || export.aliases.iter().any(|alias| alias == name)
        })
    }

    /// Find an export by ordinal.
    #[must_use]
    pub fn find_by_ordinal(&self, ordinal: u32) -> Option<&ExportedFunction> {
        self.exports.iter().find(|e| e.ordinal == ordinal)
    }

    /// Add an exported function at an RVA.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_add_export`] returns an error.
    pub fn add_export(&mut self, name: Option<&str>, rva: u32) {
        self.try_add_export(name, rva)
            .expect("export ordinal overflow: use try_add_export()");
    }

    /// Add an exported function at an RVA.
    ///
    /// The new export gets the ordinal after the highest existing ordinal.
    /// If the table has no exports, the new export gets the ordinal base.
    ///
    /// # Errors
    ///
    /// Returns [`Error::invalid_data_directory`] if the highest existing
    /// ordinal is `u32::MAX`.
    pub fn try_add_export(&mut self, name: Option<&str>, rva: u32) -> Result<()> {
        self.push_export(name, ExportAddress::Rva(rva))
    }

    /// Add a forwarded export.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_add_forwarder`] returns an error.
    pub fn add_forwarder(&mut self, name: Option<&str>, forward_to: &str) {
        self.try_add_forwarder(name, forward_to)
            .expect("export ordinal overflow: use try_add_forwarder()");
    }

    /// Add a forwarded export.
    ///
    /// The new export gets the ordinal after the highest existing ordinal.
    /// If the table has no exports, the new export gets the ordinal base.
    ///
    /// # Errors
    ///
    /// Returns [`Error::invalid_data_directory`] if the highest existing
    /// ordinal is `u32::MAX`.
    pub fn try_add_forwarder(&mut self, name: Option<&str>, forward_to: &str) -> Result<()> {
        self.push_export(name, ExportAddress::Forwarder(forward_to.to_string()))
    }

    /// Push an export with the next free ordinal.
    fn push_export(&mut self, name: Option<&str>, address: ExportAddress) -> Result<()> {
        let ordinal = match self.exports.iter().map(|e| e.ordinal).max() {
            None => self.directory.base,
            Some(highest) => highest
                .checked_add(1)
                .ok_or_else(|| Error::invalid_data_directory("export ordinal overflow"))?,
        };
        self.exports.push(ExportedFunction {
            ordinal,
            name: name.map(str::to_string),
            aliases: Vec::new(),
            address,
        });
        Ok(())
    }

    /// Set the DLL name.
    pub fn set_dll_name(&mut self, name: &str) {
        self.dll_name = name.to_string();
    }

    /// Set the ordinal base.
    pub fn set_base(&mut self, base: u32) {
        self.directory.base = base;
    }
}

/// Serialize an export table to section data.
#[derive(Debug)]
pub struct ExportTableBuilder {
    /// The RVA at which the export data starts.
    pub base_rva: u32,
}

impl ExportTableBuilder {
    /// Create a builder for export data at the RVA `base_rva`.
    #[must_use]
    pub fn new(base_rva: u32) -> Self {
        Self { base_rva }
    }

    /// Calculate the total size of the export data.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_calculate_size`] returns an error.
    #[must_use]
    pub fn calculate_size(table: &ExportTable) -> usize {
        Self::try_calculate_size(table)
            .expect("export table size overflow: use try_calculate_size()")
    }

    /// Calculate the serialized size of the export data.
    ///
    /// The function also validates sparse ordinals, names and all intermediate offsets.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - An export ordinal is below the ordinal base, or two exports have the same ordinal.
    /// - The ordinal index of a named export does not fit in `u16`.
    /// - The sparse address table is larger than the safety limit.
    /// - A name or a forwarder contains a NUL byte.
    /// - A size overflows.
    pub fn try_calculate_size(table: &ExportTable) -> Result<usize> {
        if table.exports.is_empty() && table.dll_name.is_empty() {
            return Ok(0);
        }
        Ok(export_layout(table)?.total_size)
    }

    /// Build the export data and returns (`section_data`, `export_size`).
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] returns an error.
    #[must_use]
    pub fn build(&self, table: &ExportTable) -> (Vec<u8>, u32) {
        self.try_build(table)
            .expect("export table build failed: use try_build() for fallible serialization")
    }

    /// Build the export data.
    ///
    /// The function keeps sparse EAT slots and all names of each ordinal.
    ///
    /// It returns the serialized export data and its size in bytes. The data holds, in this
    /// order:
    /// 1. The directory.
    /// 2. The address table.
    /// 3. The name pointer table and the ordinal table.
    /// 4. The strings.
    ///
    /// # Errors
    ///
    /// Returns an error for each condition of [`Self::try_calculate_size`]. Also returns an
    /// error if the serialized size, or an RVA in the range that starts at `base_rva`, does not
    /// fit in `u32`.
    pub fn try_build(&self, table: &ExportTable) -> Result<(Vec<u8>, u32)> {
        if table.exports.is_empty() && table.dll_name.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let layout = export_layout(table)?;
        let dimensions = layout.dimensions;
        let total_size_u32 = u32::try_from(layout.total_size)
            .map_err(|_| Error::invalid_data_directory("export table exceeds u32"))?;
        self.base_rva
            .checked_add(total_size_u32)
            .ok_or_else(|| Error::invalid_data_directory("export table RVA range overflow"))?;
        let mut data = vec![0u8; layout.total_size];

        let dll_name_rva = checked_rva(self.base_rva, layout.dll_name_offset, "export DLL name")?;
        put_c_string(&mut data, layout.dll_name_offset, &table.dll_name)?;
        let (mut names, string_pos) = self.write_names(&mut data, table, &layout)?;
        let eat_entries = self.write_forwarders(&mut data, table, &layout, string_pos)?;

        // Sort the named exports by name, so that a binary search can find them.
        names.sort_by(|left, right| left.name.cmp(right.name));
        write_tables(&mut data, &layout, &eat_entries, &names)?;

        // Build and write the directory.
        let directory = ExportDirectory {
            characteristics: table.directory.characteristics,
            time_date_stamp: table.directory.time_date_stamp,
            major_version: table.directory.major_version,
            minor_version: table.directory.minor_version,
            name_rva: dll_name_rva,
            base: table.directory.base,
            number_of_functions: u32::try_from(dimensions.function_count)
                .map_err(|_| Error::invalid_data_directory("export function count exceeds u32"))?,
            number_of_names: u32::try_from(dimensions.named_count)
                .map_err(|_| Error::invalid_data_directory("export name count exceeds u32"))?,
            address_of_functions: if dimensions.function_count > 0 {
                checked_rva(self.base_rva, ExportDirectory::SIZE, "export address table")?
            } else {
                0
            },
            address_of_names: if dimensions.named_count > 0 {
                checked_rva(self.base_rva, layout.name_ptr_offset, "export name table")?
            } else {
                0
            },
            address_of_name_ordinals: if dimensions.named_count > 0 {
                checked_rva(
                    self.base_rva,
                    layout.ordinal_table_offset,
                    "export ordinal table",
                )?
            } else {
                0
            },
        };
        directory.write(&mut data)?;

        Ok((data, total_size_u32))
    }

    /// Write each function name and alias at the start of the string area.
    ///
    /// Returns one entry for each written name, in table order. Also returns the offset after
    /// the last name.
    fn write_names<'a>(
        &self,
        data: &mut [u8],
        table: &'a ExportTable,
        layout: &ExportLayout,
    ) -> Result<(Vec<NameEntry<'a>>, usize)> {
        let mut string_pos = layout.strings_offset;
        let mut names = Vec::with_capacity(layout.dimensions.named_count);
        for export in &table.exports {
            if export.name.is_none() && export.aliases.is_empty() {
                continue;
            }
            let eat_index = export
                .ordinal
                .checked_sub(table.directory.base)
                .and_then(|index| u16::try_from(index).ok())
                .ok_or_else(|| {
                    Error::invalid_data_directory(
                        "named export ordinal index does not fit the u16 name table",
                    )
                })?;
            for name in export.name.iter().chain(export.aliases.iter()) {
                let rva = checked_rva(self.base_rva, string_pos, "export name")?;
                string_pos = put_c_string(data, string_pos, name)?;
                names.push(NameEntry {
                    name: name.as_str(),
                    eat_index,
                    rva,
                });
            }
        }
        Ok((names, string_pos))
    }

    /// Write the forwarder strings, starting at offset `string_pos`.
    ///
    /// Returns the sparse EAT. Each slot holds a function RVA, a forwarder string RVA, or 0 for
    /// an empty slot.
    fn write_forwarders(
        &self,
        data: &mut [u8],
        table: &ExportTable,
        layout: &ExportLayout,
        mut string_pos: usize,
    ) -> Result<Vec<u32>> {
        let mut eat_entries = vec![0u32; layout.dimensions.function_count];
        for export in &table.exports {
            let slot = export
                .ordinal
                .checked_sub(table.directory.base)
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| eat_entries.get_mut(index))
                .ok_or_else(|| Error::invalid_data_directory("export ordinal index overflow"))?;
            *slot = match &export.address {
                ExportAddress::Rva(rva) => *rva,
                ExportAddress::Forwarder(fwd) => {
                    let fwd_rva = checked_rva(self.base_rva, string_pos, "export forwarder")?;
                    string_pos = put_c_string(data, string_pos, fwd)?;
                    fwd_rva
                }
            };
        }
        Ok(eat_entries)
    }
}

/// Byte offsets of the parts of a serialized export table.
///
/// The EAT starts at [`ExportDirectory::SIZE`]. The other parts follow in
/// field order. Each offset is at most `total_size`.
#[derive(Debug, Clone, Copy)]
struct ExportLayout {
    dimensions: ExportDimensions,
    name_ptr_offset: usize,
    ordinal_table_offset: usize,
    dll_name_offset: usize,
    strings_offset: usize,
    total_size: usize,
}

/// Calculate the layout of the serialized export table with checked arithmetic.
fn export_layout(table: &ExportTable) -> Result<ExportLayout> {
    let dimensions = export_dimensions(table)?;
    let eat_size = dimensions
        .function_count
        .checked_mul(4)
        .ok_or_else(|| Error::invalid_data_directory("export address-table size overflow"))?;
    let name_ptr_size = dimensions
        .named_count
        .checked_mul(4)
        .ok_or_else(|| Error::invalid_data_directory("export name-table size overflow"))?;
    let ordinal_size = dimensions
        .named_count
        .checked_mul(2)
        .ok_or_else(|| Error::invalid_data_directory("export ordinal-table size overflow"))?;
    let dll_name_size = checked_string_size(&table.dll_name, "export DLL name")?;

    let mut names_size = 0usize;
    let mut forwarders_size = 0usize;
    for export in &table.exports {
        for name in export.name.iter().chain(export.aliases.iter()) {
            names_size = names_size
                .checked_add(checked_string_size(name, "export name")?)
                .ok_or_else(|| Error::invalid_data_directory("export names size overflow"))?;
        }
        if let ExportAddress::Forwarder(forwarder) = &export.address {
            forwarders_size = forwarders_size
                .checked_add(checked_string_size(forwarder, "export forwarder")?)
                .ok_or_else(|| Error::invalid_data_directory("export forwarder size overflow"))?;
        }
    }

    let overflow = || Error::invalid_data_directory("export table size overflow");
    let name_ptr_offset = ExportDirectory::SIZE
        .checked_add(eat_size)
        .ok_or_else(overflow)?;
    let ordinal_table_offset = name_ptr_offset
        .checked_add(name_ptr_size)
        .ok_or_else(overflow)?;
    let dll_name_offset = ordinal_table_offset
        .checked_add(ordinal_size)
        .ok_or_else(overflow)?;
    let strings_offset = dll_name_offset
        .checked_add(dll_name_size)
        .ok_or_else(overflow)?;
    let total_size = strings_offset
        .checked_add(names_size)
        .and_then(|size| size.checked_add(forwarders_size))
        .ok_or_else(overflow)?;
    Ok(ExportLayout {
        dimensions,
        name_ptr_offset,
        ordinal_table_offset,
        dll_name_offset,
        strings_offset,
        total_size,
    })
}

/// A function name that `ExportTableBuilder` wrote to the string area.
#[derive(Debug, Clone, Copy)]
struct NameEntry<'a> {
    /// The function name.
    name: &'a str,
    /// The index of the function in the EAT.
    eat_index: u16,
    /// The RVA of the name string.
    rva: u32,
}

/// Write the EAT, the name pointer table and the ordinal table.
///
/// Sort `names` by name before you call this function.
fn write_tables(
    data: &mut [u8],
    layout: &ExportLayout,
    eat_entries: &[u32],
    names: &[NameEntry<'_>],
) -> Result<()> {
    let eat = table_region(data, ExportDirectory::SIZE, layout.name_ptr_offset)?;
    for (slot, rva) in eat.as_chunks_mut::<4>().0.iter_mut().zip(eat_entries) {
        *slot = rva.to_le_bytes();
    }
    let name_ptrs = table_region(data, layout.name_ptr_offset, layout.ordinal_table_offset)?;
    for (slot, entry) in name_ptrs.as_chunks_mut::<4>().0.iter_mut().zip(names) {
        *slot = entry.rva.to_le_bytes();
    }
    let ordinals = table_region(data, layout.ordinal_table_offset, layout.dll_name_offset)?;
    for (slot, entry) in ordinals.as_chunks_mut::<2>().0.iter_mut().zip(names) {
        *slot = entry.eat_index.to_le_bytes();
    }
    Ok(())
}

/// Get the bytes from `start` to `end` of `data`.
///
/// # Errors
///
/// Returns [`Error::buffer_too_small`] if the range is not in `data`.
fn table_region(data: &mut [u8], start: usize, end: usize) -> Result<&mut [u8]> {
    let len = data.len();
    data.get_mut(start..end)
        .ok_or_else(|| Error::buffer_too_small(end, len))
}

/// Copy `value` and a NUL terminator into `data` at `offset`.
///
/// Returns the offset after the terminator.
///
/// # Errors
///
/// Returns an error if the string does not fit in `data`.
fn put_c_string(data: &mut [u8], offset: usize, value: &str) -> Result<usize> {
    let end = offset
        .checked_add(value.len())
        .and_then(|end| end.checked_add(1))
        .ok_or_else(|| Error::invalid_data_directory("export string offset overflow"))?;
    let len = data.len();
    let Some((terminator, text)) = data.get_mut(offset..end).and_then(<[u8]>::split_last_mut)
    else {
        return Err(Error::buffer_too_small(end, len));
    };
    text.copy_from_slice(value.as_bytes());
    *terminator = 0;
    Ok(end)
}

/// Read exactly `N` bytes at `rva` through `read_at_rva`.
///
/// # Errors
///
/// Returns an error if the function cannot read the bytes.
fn read_array_rva<const N: usize, F>(read_at_rva: &F, rva: u32, context: &str) -> Result<[u8; N]>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    let data = crate::parse_utils::read_exact_rva(read_at_rva, rva, N, context)?;
    data.first_chunk::<N>()
        .copied()
        .ok_or_else(|| Error::buffer_too_small(N, data.len()))
}

#[derive(Debug, Clone, Copy)]
struct ExportDimensions {
    function_count: usize,
    named_count: usize,
}

fn export_dimensions(table: &ExportTable) -> Result<ExportDimensions> {
    let mut ordinals = BTreeSet::new();
    let mut function_count = 0usize;
    let mut named_count = 0usize;
    for export in &table.exports {
        let index = export
            .ordinal
            .checked_sub(table.directory.base)
            .ok_or_else(|| {
                Error::invalid_data_directory(format!(
                    "export ordinal {} is below base {}",
                    export.ordinal, table.directory.base
                ))
            })?;
        if !ordinals.insert(export.ordinal) {
            return Err(Error::invalid_data_directory(format!(
                "duplicate export ordinal {} (use aliases for multiple names)",
                export.ordinal
            )));
        }
        let index_usize = usize::try_from(index)
            .map_err(|_| Error::invalid_data_directory("export ordinal index overflow"))?;
        function_count = function_count.max(
            index_usize
                .checked_add(1)
                .ok_or_else(|| Error::invalid_data_directory("export function count overflow"))?,
        );
        let names_for_export = usize::from(export.name.is_some())
            .checked_add(export.aliases.len())
            .ok_or_else(|| Error::invalid_data_directory("export name count overflow"))?;
        if names_for_export != 0 && index > u32::from(u16::MAX) {
            return Err(Error::invalid_data_directory(format!(
                "named export ordinal {} is too far above base {}",
                export.ordinal, table.directory.base
            )));
        }
        named_count = named_count
            .checked_add(names_for_export)
            .ok_or_else(|| Error::invalid_data_directory("export name count overflow"))?;
    }
    if function_count > MAX_EXPORT_FUNCTIONS as usize {
        return Err(Error::invalid_data_directory(format!(
            "sparse export table needs {function_count} slots, exceeding the safety limit {MAX_EXPORT_FUNCTIONS}"
        )));
    }
    Ok(ExportDimensions {
        function_count,
        named_count,
    })
}

fn checked_string_size(value: &str, context: &str) -> Result<usize> {
    if value.as_bytes().contains(&0) {
        return Err(Error::invalid_data_directory(format!(
            "{context} contains an embedded NUL byte"
        )));
    }
    value
        .len()
        .checked_add(1)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} size overflow")))
}

fn checked_rva(base: u32, offset: usize, context: &str) -> Result<u32> {
    let offset = u32::try_from(offset)
        .map_err(|_| Error::invalid_data_directory(format!("{context} offset exceeds u32")))?;
    base.checked_add(offset)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} RVA overflow")))
}

#[cfg(test)]
mod tests;
