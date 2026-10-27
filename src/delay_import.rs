//! Delay-load import directory parsing.
//!
//! The loader loads a delay-load import when the program first uses it, not at
//! program startup. Use delay-load imports for optional dependencies or to make
//! startup faster.
//!
//! # Examples
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! let delay_imports = pe.delay_imports()?;
//! for dll in &delay_imports.dlls {
//!     println!("Delay-load DLL: {}", dll.name);
//!     println!("  IAT RVA: {:#x}", dll.descriptor.import_address_table_rva);
//!     println!("  INT RVA: {:#x}", dll.descriptor.import_name_table_rva);
//! }
//! # Ok::<(), portex::Error>(())
//! ```

use crate::import::Cursor;
use crate::prelude::*;
use crate::{Error, Result};

/// `IMAGE_ORDINAL_FLAG32`: high bit of a PE32 thunk marks an import by ordinal.
const IMAGE_ORDINAL_FLAG32: u32 = 0x8000_0000;
/// `IMAGE_ORDINAL_FLAG64`: high bit of a PE32+ thunk marks an import by ordinal.
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

/// Delay-load descriptor (`IMAGE_DELAYLOAD_DESCRIPTOR`).
///
/// The address fields are RVAs in the modern format. In the legacy format
/// ([`Self::uses_rvas`] returns `false`), they are VAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DelayLoadDescriptor {
    /// Attributes. Bit 0 set means that the address fields are RVAs.
    pub attributes: u32,
    /// Address of the DLL name.
    pub dll_name_rva: u32,
    /// Address of the module handle.
    pub module_handle_rva: u32,
    /// Address of the delay-load import address table (IAT).
    pub import_address_table_rva: u32,
    /// Address of the delay-load import name table (INT).
    pub import_name_table_rva: u32,
    /// Address of the bound delay-load import address table.
    pub bound_import_address_table_rva: u32,
    /// Address of the unload delay-load import address table.
    pub unload_information_table_rva: u32,
    /// Time stamp of the bound DLL. The value is 0 if the DLL is not bound.
    pub time_date_stamp: u32,
}

impl DelayLoadDescriptor {
    /// Size of the structure in bytes.
    pub const SIZE: usize = Self::SIZE_U32 as usize;
    /// [`Self::SIZE`] as a `u32`, for RVA arithmetic.
    const SIZE_U32: u32 = 32;

    /// Parse a descriptor from raw bytes. Return `None` if the descriptor is the null terminator.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::BufferTooSmall` if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Option<Self>> {
        let Some(data) = data.first_chunk::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };

        let mut fields = [0u32; 8];
        for (field, bytes) in fields.iter_mut().zip(data.as_chunks::<4>().0) {
            *field = u32::from_le_bytes(*bytes);
        }
        let [
            attributes,
            dll_name_rva,
            module_handle_rva,
            import_address_table_rva,
            import_name_table_rva,
            bound_import_address_table_rva,
            unload_information_table_rva,
            time_date_stamp,
        ] = fields;

        // The terminator is a descriptor with all fields zero. A descriptor with only
        // some zero fields is malformed data. It is not an early end marker.
        if attributes == 0
            && dll_name_rva == 0
            && module_handle_rva == 0
            && import_address_table_rva == 0
            && import_name_table_rva == 0
            && bound_import_address_table_rva == 0
            && unload_information_table_rva == 0
            && time_date_stamp == 0
        {
            return Ok(None);
        }

        Ok(Some(Self {
            attributes,
            dll_name_rva,
            module_handle_rva,
            import_address_table_rva,
            import_name_table_rva,
            bound_import_address_table_rva,
            unload_information_table_rva,
            time_date_stamp,
        }))
    }

    /// Return `true` if the descriptor address fields are RVAs (the modern format).
    #[must_use]
    pub fn uses_rvas(&self) -> bool {
        self.attributes & 1 != 0
    }

    /// Return the fields as the on-disk structure.
    fn to_array(self) -> [u8; Self::SIZE] {
        let fields = [
            self.attributes,
            self.dll_name_rva,
            self.module_handle_rva,
            self.import_address_table_rva,
            self.import_name_table_rva,
            self.bound_import_address_table_rva,
            self.unload_information_table_rva,
            self.time_date_stamp,
        ];
        let mut buf = [0u8; Self::SIZE];
        for (bytes, field) in buf.as_chunks_mut::<4>().0.iter_mut().zip(fields) {
            *bytes = field.to_le_bytes();
        }
        buf
    }
}

/// A delay-load import entry (a function to import).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelayImportThunk {
    /// Import by ordinal.
    Ordinal(u16),
    /// Import by name, with a hint.
    Name {
        /// Hint (an index into the export name pointer table).
        hint: u16,
        /// Function name.
        name: String,
    },
}

/// A delay-loaded DLL with its descriptor, name, and imports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelayLoadedDll {
    /// The raw descriptor.
    pub descriptor: DelayLoadDescriptor,
    /// Resolved DLL name.
    pub name: String,
    /// Imported functions.
    pub imports: Vec<DelayImportThunk>,
}

/// Delay-load import directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DelayImportDirectory {
    /// Delay-loaded DLLs.
    pub dlls: Vec<DelayLoadedDll>,
}

impl DelayImportDirectory {
    /// Parse the delay import directory.
    ///
    /// # Arguments
    /// * `rva` - RVA of the delay import directory.
    /// * `is_64bit` - `true` for a PE32+ image.
    /// * `read_fn` - Function that reads data at an RVA.
    ///
    /// # Errors
    ///
    /// Returns an error if one of these conditions occurs:
    ///
    /// - A descriptor, a thunk or a name cannot be read.
    /// - A descriptor has reserved attribute bits set or has no DLL name.
    /// - An ordinal thunk has reserved bits set.
    /// - A named thunk has a null hint/name RVA.
    /// - An RVA computation overflows.
    /// - The descriptor table or a thunk table has no null terminator.
    pub fn parse<F>(rva: u32, is_64bit: bool, read_fn: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        Self::parse_bounded(rva, None, 0, is_64bit, read_fn)
    }

    /// Parse delay imports. Convert legacy descriptors, which use VAs, to RVAs with
    /// `image_base`. `image_base` is the preferred or the runtime image base.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::parse`]. Also returns an error if a nonzero legacy
    /// VA is less than `image_base`.
    pub fn parse_with_image_base<F>(
        rva: u32,
        image_base: u64,
        is_64bit: bool,
        read_fn: F,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        Self::parse_bounded(rva, None, image_base, is_64bit, read_fn)
    }

    /// Parse delay imports, and do not read descriptors past the data directory
    /// size `size`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::parse_with_image_base`]. Also returns an
    /// error if `size` is smaller than one descriptor, or if the descriptor table
    /// has no terminator in the first `size` bytes.
    pub fn parse_sized_with_image_base<F>(
        rva: u32,
        size: u32,
        image_base: u64,
        is_64bit: bool,
        read_fn: F,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        if size < DelayLoadDescriptor::SIZE_U32 {
            return Err(Error::invalid_data_directory(format!(
                "delay-import directory is {size} bytes, expected at least {}",
                DelayLoadDescriptor::SIZE
            )));
        }
        Self::parse_bounded(rva, Some(size), image_base, is_64bit, read_fn)
    }

    fn parse_bounded<F>(
        rva: u32,
        directory_size: Option<u32>,
        image_base: u64,
        is_64bit: bool,
        read_fn: F,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut dlls = Vec::new();
        let mut offset = 0u32;
        let thunk_size: u8 = if is_64bit { 8 } else { 4 };

        for _ in 0..65_536 {
            if let Some(size) = directory_size {
                let end = offset
                    .checked_add(DelayLoadDescriptor::SIZE_U32)
                    .ok_or_else(|| {
                        Error::invalid_data_directory("delay-import descriptor range overflow")
                    })?;
                if end > size {
                    return Err(Error::invalid_data_directory(
                        "delay-import descriptor table is missing a terminator within its directory",
                    ));
                }
            }
            let descriptor_rva = rva.checked_add(offset).ok_or_else(|| {
                Error::invalid_data_directory("delay-import descriptor RVA overflow")
            })?;
            let desc_data = read_fn(descriptor_rva, DelayLoadDescriptor::SIZE)
                .ok_or_else(|| Error::invalid_rva(descriptor_rva))?;

            match DelayLoadDescriptor::parse(&desc_data)? {
                Some(mut desc) => {
                    if desc.attributes & !1 != 0 {
                        return Err(Error::invalid_data_directory(format!(
                            "delay-import descriptor has reserved attributes {:#x}",
                            desc.attributes
                        )));
                    }
                    if !desc.uses_rvas() {
                        desc.dll_name_rva = va_field_to_rva(desc.dll_name_rva, image_base)?;
                        desc.module_handle_rva =
                            va_field_to_rva(desc.module_handle_rva, image_base)?;
                        desc.import_address_table_rva =
                            va_field_to_rva(desc.import_address_table_rva, image_base)?;
                        desc.import_name_table_rva =
                            va_field_to_rva(desc.import_name_table_rva, image_base)?;
                        desc.bound_import_address_table_rva =
                            va_field_to_rva(desc.bound_import_address_table_rva, image_base)?;
                        desc.unload_information_table_rva =
                            va_field_to_rva(desc.unload_information_table_rva, image_base)?;
                    }
                    if desc.dll_name_rva == 0 {
                        return Err(Error::invalid_data_directory(
                            "non-null delay-import descriptor has no DLL name",
                        ));
                    }

                    // Read the DLL name.
                    let name = if desc.dll_name_rva != 0 {
                        crate::parse_utils::read_c_string(
                            &read_fn,
                            desc.dll_name_rva,
                            256,
                            "delay-import DLL name",
                        )?
                    } else {
                        String::new()
                    };

                    // Parse the thunks from the INT (Import Name Table).
                    let imports = Self::parse_thunks(
                        desc.import_name_table_rva,
                        is_64bit,
                        thunk_size,
                        &read_fn,
                    )?;

                    dlls.push(DelayLoadedDll {
                        descriptor: desc,
                        name,
                        imports,
                    });
                    offset = offset
                        .checked_add(DelayLoadDescriptor::SIZE_U32)
                        .ok_or_else(|| {
                            Error::invalid_data_directory(
                                "delay-import descriptor table size overflow",
                            )
                        })?;
                }
                None => return Ok(Self { dlls }),
            }
        }

        Err(Error::invalid_data_directory(
            "delay-import descriptor table is missing a terminator",
        ))
    }

    fn parse_thunks<F>(
        int_rva: u32,
        is_64bit: bool,
        thunk_size: u8,
        read_fn: &F,
    ) -> Result<Vec<DelayImportThunk>>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut imports = Vec::new();
        if int_rva == 0 {
            return Ok(imports);
        }

        let mut thunk_offset = 0u32;
        let ordinal_flag = if is_64bit {
            IMAGE_ORDINAL_FLAG64
        } else {
            u64::from(IMAGE_ORDINAL_FLAG32)
        };

        for _ in 0..1_048_576 {
            let thunk_rva = int_rva
                .checked_add(thunk_offset)
                .ok_or_else(|| Error::invalid_data_directory("delay-import thunk RVA overflow"))?;
            let thunk_data = crate::parse_utils::read_exact_rva(
                read_fn,
                thunk_rva,
                usize::from(thunk_size),
                "delay-import thunk",
            )?;
            let thunk_value: u64 = if is_64bit {
                let bytes = thunk_data
                    .first_chunk::<8>()
                    .ok_or_else(|| Error::buffer_too_small(8, thunk_data.len()))?;
                u64::from_le_bytes(*bytes)
            } else {
                let bytes = thunk_data
                    .first_chunk::<4>()
                    .ok_or_else(|| Error::buffer_too_small(4, thunk_data.len()))?;
                u64::from(u32::from_le_bytes(*bytes))
            };

            // Null terminator.
            if thunk_value == 0 {
                return Ok(imports);
            }

            // Check for an import by ordinal.
            if thunk_value & ordinal_flag != 0 {
                let reserved_mask = if is_64bit {
                    0x7fff_ffff_ffff_0000
                } else {
                    0x0000_0000_7fff_0000
                };
                if thunk_value & reserved_mask != 0 {
                    return Err(Error::invalid_data_directory(
                        "delay-import ordinal thunk has nonzero reserved bits",
                    ));
                }
                let [low, high, ..] = thunk_value.to_le_bytes();
                imports.push(DelayImportThunk::Ordinal(u16::from_le_bytes([low, high])));
            } else {
                // Import by name: `thunk_value` is the RVA of the hint/name entry.
                let hint_name_rva = u32::try_from(thunk_value).map_err(|_| {
                    Error::invalid_data_directory(
                        "delay-import hint/name address does not fit an RVA",
                    )
                })?;
                if hint_name_rva == 0 {
                    return Err(Error::invalid_data_directory(
                        "named delay import has a null hint/name RVA",
                    ));
                }
                let hint_name_data = crate::parse_utils::read_exact_rva(
                    read_fn,
                    hint_name_rva,
                    2,
                    "delay-import hint",
                )?;
                let hint_bytes = hint_name_data
                    .first_chunk::<2>()
                    .ok_or_else(|| Error::buffer_too_small(2, hint_name_data.len()))?;
                let hint = u16::from_le_bytes(*hint_bytes);
                let name_rva = hint_name_rva.checked_add(2).ok_or_else(|| {
                    Error::invalid_data_directory("delay-import hint/name RVA overflow")
                })?;
                let name = crate::parse_utils::read_c_string(
                    read_fn,
                    name_rva,
                    256,
                    "delay-import function name",
                )?;
                imports.push(DelayImportThunk::Name { hint, name });
            }

            thunk_offset = thunk_offset
                .checked_add(u32::from(thunk_size))
                .ok_or_else(|| {
                    Error::invalid_data_directory("delay-import thunk table size overflow")
                })?;
        }

        Err(Error::invalid_data_directory(
            "delay-import thunk table is missing a terminator",
        ))
    }
}

fn va_field_to_rva(value: u32, image_base: u64) -> Result<u32> {
    if value == 0 {
        return Ok(0);
    }
    u64::from(value)
        .checked_sub(image_base)
        .and_then(|rva| u32::try_from(rva).ok())
        .ok_or_else(|| {
            Error::invalid_data_directory(format!(
                "legacy delay-import VA {value:#x} is outside image base {image_base:#x}"
            ))
        })
}

/// Builder that serializes delay-load import tables.
#[derive(Debug)]
pub struct DelayImportBuilder {
    /// If `true`, build for PE32+. If `false`, build for PE32.
    pub is_64bit: bool,
    /// RVA of the start of the built delay import data.
    pub base_rva: u32,
}

impl DelayImportBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new(is_64bit: bool, base_rva: u32) -> Self {
        Self { is_64bit, base_rva }
    }

    /// Calculate the total size of the delay import data.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_calculate_size`] fails.
    #[must_use]
    pub fn calculate_size(&self, dlls: &[DelayLoadedDll]) -> usize {
        self.try_calculate_size(dlls)
            .expect("delay-import size overflow: use try_calculate_size()")
    }

    /// Calculate the size. Use checked arithmetic for the descriptor, thunk,
    /// handle and name counts.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data-directory error if a DLL name or a function name
    /// is empty or contains NUL. Also returns this error if a size computation
    /// overflows `usize`.
    pub fn try_calculate_size(&self, dlls: &[DelayLoadedDll]) -> Result<usize> {
        if dlls.is_empty() {
            return Ok(0);
        }
        Ok(self.layout(dlls)?.total_size)
    }

    /// Validate the names in `dlls` and calculate the layout of the built
    /// table. Do not call this function for an empty list.
    fn layout(&self, dlls: &[DelayLoadedDll]) -> Result<DelayImportLayout> {
        let thunk_size = self.thunk_size();

        // Descriptors: one for each DLL, plus a null terminator.
        let descriptors_size = dlls
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(DelayLoadDescriptor::SIZE))
            .ok_or_else(|| {
                Error::invalid_data_directory("delay-import descriptor size overflow")
            })?;

        // IAT and INT. Each has the thunks of each DLL plus a null terminator for each DLL.
        let mut thunks_count = 0usize;
        for dll in dlls {
            if dll.name.is_empty() || dll.name.as_bytes().contains(&0) {
                return Err(Error::invalid_data_directory(
                    "delay-import DLL names must be nonempty and contain no NUL bytes",
                ));
            }
            thunks_count = thunks_count
                .checked_add(dll.imports.len().checked_add(1).ok_or_else(|| {
                    Error::invalid_data_directory("delay-import thunk count overflow")
                })?)
                .ok_or_else(|| {
                    Error::invalid_data_directory("delay-import thunk count overflow")
                })?;
        }
        // The IAT and INT have the same size.
        let thunk_table_size = thunks_count.checked_mul(thunk_size).ok_or_else(|| {
            Error::invalid_data_directory("delay-import thunk table size overflow")
        })?;

        // Module handles: one `HMODULE` pointer for each DLL.
        let handles_size = dlls
            .len()
            .checked_mul(thunk_size)
            .ok_or_else(|| Error::invalid_data_directory("delay-import handle size overflow"))?;

        // Hint/name entries.
        let mut hint_names_size = 0usize;
        for dll in dlls {
            for import in &dll.imports {
                if let DelayImportThunk::Name { name, .. } = import {
                    if name.is_empty() || name.as_bytes().contains(&0) {
                        return Err(Error::invalid_data_directory(
                            "delay-import names must be nonempty and contain no NUL bytes",
                        ));
                    }
                    // Each entry: 2-byte hint, name, null terminator, padding to an even size.
                    let entry_size = name.len().checked_add(3).ok_or_else(|| {
                        Error::invalid_data_directory("delay-import name size overflow")
                    })?;
                    let aligned = entry_size.checked_add(1).ok_or_else(|| {
                        Error::invalid_data_directory("delay-import name alignment overflow")
                    })? & !1;
                    hint_names_size = hint_names_size.checked_add(aligned).ok_or_else(|| {
                        Error::invalid_data_directory("delay-import names size overflow")
                    })?;
                }
            }
        }

        // DLL names.
        let mut dll_names_size = 0usize;
        for dll in dlls {
            dll_names_size = dll_names_size
                .checked_add(dll.name.len().checked_add(1).ok_or_else(|| {
                    Error::invalid_data_directory("delay-import DLL name size overflow")
                })?)
                .ok_or_else(|| {
                    Error::invalid_data_directory("delay-import DLL names size overflow")
                })?;
        }

        let overflow = || Error::invalid_data_directory("delay-import table size overflow");
        let name_table_offset = descriptors_size
            .checked_add(thunk_table_size) // IAT
            .ok_or_else(overflow)?;
        let handles_offset = name_table_offset
            .checked_add(thunk_table_size) // INT
            .ok_or_else(overflow)?;
        let hint_names_offset = handles_offset
            .checked_add(handles_size)
            .ok_or_else(overflow)?;
        let dll_names_offset = hint_names_offset
            .checked_add(hint_names_size)
            .ok_or_else(overflow)?;
        let total_size = dll_names_offset
            .checked_add(dll_names_size)
            .ok_or_else(overflow)?;
        Ok(DelayImportLayout {
            descriptors_size,
            name_table_offset,
            handles_offset,
            hint_names_offset,
            dll_names_offset,
            total_size,
        })
    }

    /// Build the delay import data and return `(section_data, size)`.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] fails.
    #[must_use]
    pub fn build(&self, dlls: &[DelayLoadedDll]) -> (Vec<u8>, u32) {
        self.try_build(dlls)
            .expect("delay-import build failed: use try_build() for fallible serialization")
    }

    /// Build a delay import table. Use checked RVAs and sizes.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::try_calculate_size`]. Also returns an
    /// invalid-data-directory error if one of these conditions occurs:
    ///
    /// - The table is larger than `u32`.
    /// - The RVA range of the table overflows.
    /// - For PE32, an RVA reaches the ordinal flag bit.
    pub fn try_build(&self, dlls: &[DelayLoadedDll]) -> Result<(Vec<u8>, u32)> {
        if dlls.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let layout = self.layout(dlls)?;
        let total_size_u32 = u32::try_from(layout.total_size)
            .map_err(|_| Error::invalid_data_directory("delay-import table exceeds u32"))?;
        let end = self
            .base_rva
            .checked_add(total_size_u32)
            .ok_or_else(|| Error::invalid_data_directory("delay-import RVA range overflow"))?;
        if !self.is_64bit && end > IMAGE_ORDINAL_FLAG32 {
            return Err(Error::invalid_data_directory(
                "PE32 delay-import RVAs would overlap the ordinal flag",
            ));
        }
        let data = self.write_table(dlls, &layout)?;
        Ok((data, total_size_u32))
    }

    /// Serialize `dlls` into a new buffer with the parts at the offsets in
    /// `layout`.
    fn write_table(&self, dlls: &[DelayLoadedDll], layout: &DelayImportLayout) -> Result<Vec<u8>> {
        let thunk_size = self.thunk_size();
        let mut data = vec![0u8; layout.total_size];

        // The parts are in this order: descriptors, IAT, INT, module handles,
        // hint/name entries, DLL names. The IAT starts after the descriptors.
        let mut desc = Cursor::new(0);
        let mut iat = Cursor::new(layout.descriptors_size);
        let mut name_table = Cursor::new(layout.name_table_offset);
        let mut handle = Cursor::new(layout.handles_offset);
        let mut hint_name = Cursor::new(layout.hint_names_offset);
        let mut dll_name = Cursor::new(layout.dll_names_offset);

        for dll in dlls {
            // Write the descriptor. Attributes value 1 means that the fields are RVAs
            // (the modern format).
            let descriptor = DelayLoadDescriptor {
                attributes: 1,
                dll_name_rva: self.rva_at(dll_name.offset())?,
                module_handle_rva: self.rva_at(handle.offset())?,
                import_address_table_rva: self.rva_at(iat.offset())?,
                import_name_table_rva: self.rva_at(name_table.offset())?,
                bound_import_address_table_rva: 0,
                unload_information_table_rva: 0,
                time_date_stamp: 0,
            };
            desc.put(&mut data, &descriptor.to_array())?;

            // Write the DLL name. The zeroed buffer supplies the null terminator.
            dll_name.put(&mut data, dll.name.as_bytes())?;
            dll_name.skip(1)?;

            // Write the IAT entries, the INT entries and the hint/name entries.
            for import in &dll.imports {
                let (by_ordinal, thunk_value) = match import {
                    DelayImportThunk::Ordinal(ord) => (true, u32::from(*ord)),
                    DelayImportThunk::Name { hint, name } => {
                        // Write the hint/name entry: hint, name, null terminator,
                        // and padding to an even offset.
                        let hint_name_rva = self.rva_at(hint_name.offset())?;
                        hint_name.put(&mut data, &hint.to_le_bytes())?;
                        hint_name.put(&mut data, name.as_bytes())?;
                        hint_name.skip(1)?;
                        hint_name.align_even()?;

                        (false, hint_name_rva)
                    }
                };
                self.write_thunk(&mut iat, &mut data, by_ordinal, thunk_value)?;
                self.write_thunk(&mut name_table, &mut data, by_ordinal, thunk_value)?;
            }

            // Skip the null terminators of the IAT and the INT, and the zeroed module handle.
            iat.skip(thunk_size)?;
            name_table.skip(thunk_size)?;
            handle.skip(thunk_size)?;
        }

        // The null terminator descriptor is already zero.

        Ok(data)
    }

    /// Size of one thunk or module handle: 8 bytes for PE32+, 4 bytes for PE32.
    fn thunk_size(&self) -> usize {
        if self.is_64bit { 8 } else { 4 }
    }

    /// Return the RVA of byte `offset` in the built delay import data.
    fn rva_at(&self, offset: usize) -> Result<u32> {
        u32::try_from(offset)
            .ok()
            .and_then(|offset| self.base_rva.checked_add(offset))
            .ok_or_else(|| Error::invalid_data_directory("delay-import RVA overflow"))
    }

    /// Write one IAT/INT thunk at `cursor`: an ordinal (with the ordinal flag
    /// set) or a hint/name RVA, sized for PE32 or PE32+.
    fn write_thunk(
        &self,
        cursor: &mut Cursor,
        data: &mut [u8],
        by_ordinal: bool,
        value: u32,
    ) -> Result<()> {
        if self.is_64bit {
            let flag = if by_ordinal { IMAGE_ORDINAL_FLAG64 } else { 0 };
            cursor.put(data, &(flag | u64::from(value)).to_le_bytes())
        } else {
            let flag = if by_ordinal { IMAGE_ORDINAL_FLAG32 } else { 0 };
            cursor.put(data, &(flag | value).to_le_bytes())
        }
    }
}

/// Offsets and sizes of the parts of a built delay-import table.
///
/// The parts are in this order: descriptors, IAT, INT, module handles,
/// hint/name entries, DLL names. The IAT starts at `descriptors_size`.
struct DelayImportLayout {
    /// Size of the descriptor array, with its null terminator.
    descriptors_size: usize,
    /// Offset of the INT in the built buffer.
    name_table_offset: usize,
    /// Offset of the module handles in the built buffer.
    handles_offset: usize,
    /// Offset of the first hint/name entry in the built buffer.
    hint_names_offset: usize,
    /// Offset of the first DLL name in the built buffer.
    dll_names_offset: usize,
    /// Size of the full table.
    total_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delay_load_descriptor_size() {
        assert_eq!(DelayLoadDescriptor::SIZE, 32);
    }

    #[test]
    fn test_null_terminator() {
        let data = [0u8; 32];
        let desc = DelayLoadDescriptor::parse(&data).unwrap();
        assert!(desc.is_none());
    }

    #[test]
    fn test_buffer_too_small() {
        let data = [0u8; 31];
        assert!(DelayLoadDescriptor::parse(&data).is_err());
    }

    #[test]
    fn test_builder_empty() {
        let builder = DelayImportBuilder::new(false, 0x1000);
        let (data, size) = builder.build(&[]);
        assert_eq!(data, Vec::<u8>::new());
        assert_eq!(size, 0);
    }

    #[test]
    fn test_builder_calculates_size() {
        let builder = DelayImportBuilder::new(false, 0x1000);
        let dlls = vec![DelayLoadedDll {
            descriptor: DelayLoadDescriptor {
                attributes: 1,
                dll_name_rva: 0,
                module_handle_rva: 0,
                import_address_table_rva: 0,
                import_name_table_rva: 0,
                bound_import_address_table_rva: 0,
                unload_information_table_rva: 0,
                time_date_stamp: 0,
            },
            name: "test.dll".to_string(),
            imports: vec![DelayImportThunk::Name {
                hint: 0,
                name: "TestFunc".to_string(),
            }],
        }];
        let size = builder.calculate_size(&dlls);
        assert!(size > 0);
    }

    #[test]
    fn test_builder_roundtrip_both_widths() {
        let dlls = vec![DelayLoadedDll {
            descriptor: DelayLoadDescriptor {
                attributes: 1,
                dll_name_rva: 0,
                module_handle_rva: 0,
                import_address_table_rva: 0,
                import_name_table_rva: 0,
                bound_import_address_table_rva: 0,
                unload_information_table_rva: 0,
                time_date_stamp: 0,
            },
            name: "test.dll".to_string(),
            imports: vec![
                DelayImportThunk::Name {
                    hint: 3,
                    name: "TestFunc".to_string(),
                },
                DelayImportThunk::Ordinal(42),
            ],
        }];
        for is_64bit in [false, true] {
            let base_rva = 0x4000u32;
            let (data, size) = DelayImportBuilder::new(is_64bit, base_rva).build(&dlls);
            assert_eq!(usize::try_from(size).unwrap(), data.len());
            let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
                let offset = usize::try_from(rva.checked_sub(base_rva)?).ok()?;
                let end = offset.checked_add(len)?.min(data.len());
                data.get(offset..end).map(<[u8]>::to_vec)
            };
            let parsed = DelayImportDirectory::parse(base_rva, is_64bit, read_fn).unwrap();
            assert_eq!(parsed.dlls.len(), 1);
            assert_eq!(parsed.dlls[0].name, "test.dll");
            assert_eq!(parsed.dlls[0].imports, dlls[0].imports);
        }
    }

    #[test]
    fn test_builder_pe32_layout() {
        let dlls = vec![DelayLoadedDll {
            descriptor: DelayLoadDescriptor::parse(&[1; 32]).unwrap().unwrap(),
            name: "test.dll".to_string(),
            imports: vec![
                DelayImportThunk::Name {
                    hint: 3,
                    name: "TestFunc".to_string(),
                },
                DelayImportThunk::Ordinal(42),
            ],
        }];
        let (data, size) = DelayImportBuilder::new(false, 0x4000).build(&dlls);
        // Descriptors 0..64, IAT 64..76, INT 76..88, handle 88..92,
        // hint/name 92..104, DLL name 104..113.
        assert_eq!((data.len(), size), (113, 113));
        let descriptor = DelayLoadDescriptor::parse(&data).unwrap().unwrap();
        assert_eq!(
            descriptor,
            DelayLoadDescriptor {
                attributes: 1,
                dll_name_rva: 0x4068,
                module_handle_rva: 0x4058,
                import_address_table_rva: 0x4040,
                import_name_table_rva: 0x404C,
                bound_import_address_table_rva: 0,
                unload_information_table_rva: 0,
                time_date_stamp: 0,
            }
        );
        assert_eq!(descriptor.to_array().as_slice(), &data[..32]);
        assert!(data[32..64].iter().all(|&byte| byte == 0));
        let thunks: Vec<u8> = [0x405Cu32, 0x8000_002A, 0]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        assert_eq!(&data[64..76], thunks.as_slice());
        assert_eq!(&data[76..88], thunks.as_slice());
        assert_eq!(&data[88..92], &[0; 4]);
        assert_eq!(&data[92..104], b"\x03\x00TestFunc\0\0");
        assert_eq!(&data[104..], b"test.dll\0");
    }
}
