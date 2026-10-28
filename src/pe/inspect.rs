use super::{MAX_NUMBER_OF_SECTIONS, PeImage, SourceLayout};
use crate::layout;
use crate::optional::OptionalHeader;
use crate::prelude::*;
use crate::section::Section;
use crate::{Error, Result};

impl PeImage {
    /// Return `true` if this is a 64-bit (PE32+) image.
    #[must_use]
    pub fn is_64bit(&self) -> bool {
        self.optional_header.is_pe32plus()
    }

    /// Return `true` if this image is a DLL.
    #[must_use]
    pub fn is_dll(&self) -> bool {
        self.coff_header.is_dll()
    }

    /// Return the section with the given name.
    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name() == name)
    }

    /// Return the section with the given name, as a mutable reference.
    pub fn section_by_name_mut(&mut self, name: &str) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| s.name() == name)
    }

    /// Find the section containing an RVA.
    #[must_use]
    pub fn section_by_rva(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    /// Find the section that contains an RVA, as a mutable reference.
    #[must_use]
    pub fn section_by_rva_mut(&mut self, rva: u32) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| s.contains_rva(rva))
    }

    /// Read `len` bytes at an RVA from one section.
    #[must_use]
    pub fn read_at_rva(&self, rva: u32, len: usize) -> Option<&[u8]> {
        self.section_by_rva(rva)?.data_at_rva(rva, len)
    }

    /// Read `len` bytes at an RVA into a new buffer.
    ///
    /// The range can be in the PE headers. It can also cross the boundary between contiguous
    /// sections. As in the loader view, these bytes read as zero:
    ///
    /// - The header bytes after the header data and before `SizeOfHeaders`.
    /// - The bytes of a section after its complete raw data and before its virtual end.
    ///
    /// The result is `None` if the range is not in the image. It is also `None` if the read adds
    /// more zero bytes than the image holds in its header data and section data. This limit
    /// keeps the memory use of a read in proportion to the input, also if `SizeOfHeaders` or
    /// `VirtualSize` is very large.
    #[must_use]
    pub fn read_rva(&self, rva: u32, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }

        let end_rva = u64::from(rva).checked_add(len as u64)?;
        if end_rva > u64::from(self.optional_header.size_of_image()) {
            return None;
        }
        if !self.contains_rva_range(rva, len) {
            return None;
        }

        // Each output byte is a copy of a held byte or a zero byte. Thus a read that adds at most
        // `held` zero bytes is at most `2 * held` bytes long.
        let held = self.held_len();
        if len > held.saturating_mul(2) {
            return None;
        }
        let mut zero_budget = held;
        let mut output = Vec::new();
        output.try_reserve_exact(len).ok()?;
        let mut current_rva = rva;
        while output.len() < len {
            if current_rva < self.optional_header.size_of_headers() {
                let header_bytes = self.build_headers().ok()?;
                let start = current_rva as usize;
                let header_limit = self.optional_header.size_of_headers() as usize;
                let available = header_limit.checked_sub(start)?;
                let count = available.min(len - output.len());
                if count == 0 {
                    return None;
                }
                let initialized = header_bytes.len().saturating_sub(start).min(count);
                zero_budget = zero_budget.checked_sub(count - initialized)?;
                if initialized != 0 {
                    output.extend_from_slice(&header_bytes[start..start + initialized]);
                }
                output.resize(output.len() + count - initialized, 0);
                current_rva = current_rva.checked_add(u32::try_from(count).ok()?)?;
                continue;
            }

            let section = self.section_by_rva(current_rva)?;
            let section_offset = current_rva.checked_sub(section.header.virtual_address)? as usize;
            let available = mapped_extent(section).checked_sub(section_offset)?;
            let count = available.min(len - output.len());
            if count == 0 {
                return None;
            }
            let initialized = section.data.len().saturating_sub(section_offset).min(count);
            zero_budget = zero_budget.checked_sub(count - initialized)?;
            if initialized != 0 {
                output
                    .extend_from_slice(&section.data[section_offset..section_offset + initialized]);
            }
            output.resize(output.len() + count - initialized, 0);
            current_rva = current_rva.checked_add(u32::try_from(count).ok()?)?;
        }

        Some(output)
    }

    /// Return the number of bytes that the image holds: the header data and the section data.
    ///
    /// The header data ends at the section table or at the header tail after it.
    fn held_len(&self) -> usize {
        let headers = usize::try_from(self.dos_header.e_lfanew)
            .ok()
            .and_then(|pe_offset| {
                layout::headers_size_at(
                    pe_offset,
                    self.sections.len(),
                    usize::from(self.coff_header.size_of_optional_header),
                )
            })
            .and_then(|table_end| self.header_data_end(table_end))
            .unwrap_or(0);
        self.sections.iter().fold(headers, |total, section| {
            total.saturating_add(section.data.len())
        })
    }

    /// Check if an RVA range is in the headers or in the sections, without allocating or copying
    /// it.
    ///
    /// The check uses the extents of [`Self::read_rva`]. Thus the zero bytes after the raw data
    /// of a section are in the range, but [`Self::read_at_rva`] cannot borrow them.
    /// [`Self::read_rva`] can also reject a range that this method accepts, if the read adds too
    /// many zero bytes.
    #[must_use]
    pub fn contains_rva_range(&self, rva: u32, len: usize) -> bool {
        if len == 0 {
            return rva <= self.optional_header.size_of_image();
        }
        let Ok(len_u64) = u64::try_from(len) else {
            return false;
        };
        let Some(end) = u64::from(rva).checked_add(len_u64) else {
            return false;
        };
        if end > u64::from(self.optional_header.size_of_image()) {
            return false;
        }

        let mut current = rva;
        let mut remaining = len;
        while remaining != 0 {
            if current < self.optional_header.size_of_headers() {
                let available = (self.optional_header.size_of_headers() - current) as usize;
                let count = available.min(remaining);
                let Ok(count_u32) = u32::try_from(count) else {
                    return false;
                };
                let Some(next) = current.checked_add(count_u32) else {
                    return false;
                };
                current = next;
                remaining -= count;
                continue;
            }
            let Some(section) = self.section_by_rva(current) else {
                return false;
            };
            let Some(relative) = current.checked_sub(section.header.virtual_address) else {
                return false;
            };
            let Some(available) = mapped_extent(section).checked_sub(relative as usize) else {
                return false;
            };
            let count = available.min(remaining);
            if count == 0 {
                return false;
            }
            let Ok(count_u32) = u32::try_from(count) else {
                return false;
            };
            let Some(next) = current.checked_add(count_u32) else {
                return false;
            };
            current = next;
            remaining -= count;
        }
        true
    }

    /// Write data at an RVA in one section.
    #[must_use]
    pub fn write_at_rva(&mut self, rva: u32, data: &[u8]) -> Option<()> {
        let section = self.section_by_rva_mut(rva)?;
        let slice = section.data_at_rva_mut(rva, data.len())?;
        slice.copy_from_slice(data);
        Some(())
    }

    /// Convert an RVA to a source offset for the given layout.
    ///
    /// The offset is relative to the start of the image. If you use [`Self::read_from`] with a
    /// nonzero `base_offset`, add that base to the offset before you read from the original
    /// source.
    #[must_use]
    pub fn rva_to_source_offset(&self, rva: u32, layout: SourceLayout) -> Option<u32> {
        if rva >= self.optional_header.size_of_image() {
            return None;
        }

        match layout {
            SourceLayout::Mapped => Some(rva),
            SourceLayout::File => {
                if rva < self.optional_header.size_of_headers() {
                    return Some(rva);
                }
                self.sections
                    .iter()
                    .find_map(|section| section.header.rva_to_offset(rva))
            }
        }
    }

    /// Convert an RVA to a file offset in the raw file.
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        self.rva_to_source_offset(rva, SourceLayout::File)
    }

    /// Add a new section.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_add_section`] fails. This occurs if the image already has
    /// [`MAX_NUMBER_OF_SECTIONS`] sections, or if the section data is larger than `u32::MAX`
    /// bytes.
    pub fn add_section(&mut self, section: Section) {
        self.try_add_section(section)
            .expect("too many PE sections: use try_add_section() for fallible updates");
    }

    /// Add a section, and apply the section limit for executable images.
    ///
    /// # Errors
    ///
    /// Returns an error if the image already has [`MAX_NUMBER_OF_SECTIONS`] sections, or if
    /// the section data is larger than `u32::MAX` bytes.
    pub fn try_add_section(&mut self, section: Section) -> Result<()> {
        if self.sections.len() >= MAX_NUMBER_OF_SECTIONS {
            return Err(Error::invalid_section(format!(
                "section count would exceed the PE image limit of {MAX_NUMBER_OF_SECTIONS}"
            )));
        }
        u32::try_from(section.data.len())
            .map_err(|_| Error::invalid_section("section data exceeds u32"))?;
        self.sections.push(section);
        self.coff_header.number_of_sections = u16::try_from(self.sections.len())
            .map_err(|_| Error::invalid_section("section count exceeds u16"))?;
        Ok(())
    }

    /// Remove the section with the given name.
    pub fn remove_section(&mut self, name: &str) -> Option<Section> {
        let idx = self.sections.iter().position(|s| s.name() == name)?;
        let removed = self.sections.remove(idx);
        self.coff_header.number_of_sections =
            u16::try_from(self.sections.len()).unwrap_or(u16::MAX);
        Some(removed)
    }

    /// Return the RVA of the entry point.
    #[must_use]
    pub fn entry_point(&self) -> u32 {
        self.optional_header.address_of_entry_point()
    }

    /// Return the preferred image base (a VA) from the optional header.
    #[must_use]
    pub fn image_base(&self) -> u64 {
        self.optional_header.image_base()
    }

    /// Return the layout of the source that this image was parsed from.
    #[must_use]
    pub const fn source_layout(&self) -> SourceLayout {
        self.source_layout
    }

    /// Return the actual mapped base (a VA). If it is not set, return the preferred image base.
    #[must_use]
    pub fn runtime_image_base(&self) -> u64 {
        self.runtime_image_base.unwrap_or_else(|| self.image_base())
    }

    /// Set the actual mapped base (a VA). Directories that contain VAs use this base.
    pub fn set_runtime_image_base(&mut self, runtime_image_base: u64) {
        self.runtime_image_base = Some(runtime_image_base);
    }

    /// Convert an RVA to a VA with the actual mapped base, if it is known.
    #[must_use]
    pub fn rva_to_runtime_va(&self, rva: u32) -> Option<u64> {
        self.rva_to_va_at(rva, self.runtime_image_base())
    }

    /// Convert a runtime VA to an RVA with the actual mapped base, if it is known.
    #[must_use]
    pub fn runtime_va_to_rva(&self, va: u64) -> Option<u32> {
        self.va_to_rva_at(va, self.runtime_image_base())
    }

    /// Convert an RVA to a VA with the preferred image base.
    #[must_use]
    pub fn rva_to_va(&self, rva: u32) -> Option<u64> {
        self.rva_to_va_at(rva, self.image_base())
    }

    /// Convert an RVA to a VA with the given runtime image base (a VA).
    #[must_use]
    pub fn rva_to_va_at(&self, rva: u32, runtime_image_base: u64) -> Option<u64> {
        (rva < self.optional_header.size_of_image())
            .then(|| runtime_image_base.checked_add(u64::from(rva)))?
    }

    /// Convert a VA that uses the preferred image base to an RVA.
    #[must_use]
    pub fn va_to_rva(&self, va: u64) -> Option<u32> {
        self.va_to_rva_at(va, self.image_base())
    }

    /// Convert a VA to an RVA with the given runtime image base (a VA).
    #[must_use]
    pub fn va_to_rva_at(&self, va: u64, runtime_image_base: u64) -> Option<u32> {
        let relative = va.checked_sub(runtime_image_base)?;
        let rva = u32::try_from(relative).ok()?;
        (rva < self.optional_header.size_of_image()).then_some(rva)
    }

    /// Return the raw bytes of a standard data directory whose address is an RVA.
    ///
    /// Use this as the lossless fallback for versioned or architecture-specific directory
    /// formats. This function rejects the Security directory, because its address is a file
    /// offset. For a full raw-file view, use [`crate::PeFile::directory_data`].
    ///
    /// # Errors
    ///
    /// Returns an error if `dir_type` is the Security directory. Also returns an error if the
    /// entry has only one of its RVA and size set, or if the image cannot supply the RVA range
    /// of the directory.
    pub fn directory_data(
        &self,
        dir_type: crate::data_dir::DataDirectoryType,
    ) -> Result<Option<Vec<u8>>> {
        use crate::data_dir::DataDirectoryType;

        let Some(directory) = self.data_directory(dir_type).filter(|dir| dir.is_present()) else {
            return Ok(None);
        };
        if dir_type == DataDirectoryType::Security {
            return Err(Error::invalid_data_directory(
                "the Security directory uses a file offset; parse the image with PeFile",
            ));
        }
        if directory.virtual_address == 0 || directory.size == 0 {
            return Err(Error::invalid_data_directory(format!(
                "{} directory has only one of address/size set",
                dir_type.name()
            )));
        }

        self.read_rva(directory.virtual_address, directory.size as usize)
            .map(Some)
            .ok_or_else(|| {
                Error::invalid_data_directory(format!(
                    "{} directory range {:#x}..+{:#x} is not readable",
                    dir_type.name(),
                    directory.virtual_address,
                    directory.size
                ))
            })
    }

    /// Return the data directory entry (`IMAGE_DATA_DIRECTORY`) of the given type.
    #[must_use]
    pub fn data_directory(
        &self,
        dir_type: crate::data_dir::DataDirectoryType,
    ) -> Option<&crate::data_dir::DataDirectory> {
        self.optional_header
            .data_directories()
            .get(dir_type.as_index())
    }

    /// Return the data directory entry (`IMAGE_DATA_DIRECTORY`) at an index (advanced use).
    #[must_use]
    pub fn data_directory_by_index(&self, index: usize) -> Option<&crate::data_dir::DataDirectory> {
        self.optional_header.data_directories().get(index)
    }

    /// Parse the import table.
    ///
    /// Returns an empty table if the import directory is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the import descriptors (`IMAGE_IMPORT_DESCRIPTOR`), thunks, or names
    /// cannot be read or are malformed.
    #[must_use = "parsing returns an import table that should be used"]
    pub fn imports(&self) -> Result<crate::import::ImportTable> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Import)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> { self.read_rva(rva, len) };
                crate::import::ImportTable::parse_sized(
                    d.virtual_address,
                    d.size,
                    self.is_64bit(),
                    read_fn,
                )
            }
            None => Ok(crate::import::ImportTable::default()),
        }
    }

    /// Parse the export table.
    ///
    /// Returns an empty table if the export directory is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the `IMAGE_EXPORT_DIRECTORY` or its address, name, or ordinal tables
    /// cannot be read or are malformed.
    #[must_use = "parsing returns an export table that should be used"]
    pub fn exports(&self) -> Result<crate::export::ExportTable> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Export)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> { self.read_rva(rva, len) };
                crate::export::ExportTable::parse(d.virtual_address, d.size, read_fn)
            }
            None => Ok(crate::export::ExportTable::default()),
        }
    }

    /// Parse the base relocation table.
    ///
    /// Returns an empty table if the base relocation directory is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if a base relocation block (`IMAGE_BASE_RELOCATION`) cannot be read or
    /// is malformed.
    #[must_use = "parsing returns a relocation table that should be used"]
    pub fn relocations(&self) -> Result<crate::reloc::RelocationTable> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::BaseReloc)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> { self.read_rva(rva, len) };
                crate::reloc::RelocationTable::parse(d.virtual_address, d.size, read_fn)
            }
            None => Ok(crate::reloc::RelocationTable::default()),
        }
    }

    /// Set the RVA and size of the data directory entry of the given type.
    pub fn set_data_directory(
        &mut self,
        dir_type: crate::data_dir::DataDirectoryType,
        rva: u32,
        size: u32,
    ) {
        self.store_data_directory(dir_type.as_index(), rva, size);
    }

    /// Set the RVA and size of the data directory entry at an index (advanced use).
    ///
    /// # Errors
    ///
    /// Returns an error if `index` is too large. The `SizeOfOptionalHeader` field is a `u16`,
    /// so the optional header cannot hold a data-directory array of that length.
    pub fn set_data_directory_by_index(&mut self, index: usize, rva: u32, size: u32) -> Result<()> {
        let base_size = match &self.optional_header {
            OptionalHeader::Pe32(_) => crate::optional::OptionalHeader32::BASE_SIZE,
            OptionalHeader::Pe32Plus(_) => crate::optional::OptionalHeader64::BASE_SIZE,
        };
        let max_count = (usize::from(u16::MAX) - base_size) / crate::data_dir::DataDirectory::SIZE;
        if index >= max_count {
            return Err(Error::invalid_data_directory(format!(
                "directory index {index} cannot fit in a PE optional header"
            )));
        }
        self.store_data_directory(index, rva, size);
        Ok(())
    }

    /// Store a data-directory entry. If necessary, grow the array and update
    /// `NumberOfRvaAndSizes`. The caller must validate `index` first.
    fn store_data_directory(&mut self, index: usize, rva: u32, size: u32) {
        let dirs = self.optional_header.data_directories_mut();
        if dirs.len() <= index {
            dirs.resize(index + 1, crate::data_dir::DataDirectory::default());
        }
        dirs[index].virtual_address = rva;
        dirs[index].size = size;

        let count = u32::try_from(dirs.len()).unwrap_or(u32::MAX);
        match &mut self.optional_header {
            OptionalHeader::Pe32(header) => header.number_of_rva_and_sizes = count,
            OptionalHeader::Pe32Plus(header) => header.number_of_rva_and_sizes = count,
        }
    }

    pub(super) fn ensure_data_directory_slot(
        &mut self,
        dir_type: crate::data_dir::DataDirectoryType,
    ) -> Result<()> {
        let index = dir_type.as_index();
        if self.optional_header.data_directories().len() <= index {
            self.set_data_directory_by_index(index, 0, 0)?;
        }
        Ok(())
    }

    /// Clear the data directory entry of the given type.
    ///
    /// If the data-directory array has no entry of this type, the function does nothing. It does
    /// not grow the array or change `NumberOfRvaAndSizes`.
    ///
    /// The bound import table can be in the header bytes after the section table. If you clear
    /// the `BoundImport` entry, the function also removes the table from these bytes. Then the
    /// build writes zeros in its place.
    pub fn clear_data_directory(&mut self, dir_type: crate::data_dir::DataDirectoryType) {
        let Some(entry) = self
            .optional_header
            .data_directories_mut()
            .get_mut(dir_type.as_index())
        else {
            return;
        };
        let old = core::mem::take(entry);
        if dir_type == crate::data_dir::DataDirectoryType::BoundImport {
            self.header_tail
                .clear_rva_range(old.virtual_address, old.size);
        }
    }

    /// Append data to a section, and return the RVA of the data.
    ///
    /// Returns `None` if the section does not exist.
    pub fn append_to_section(&mut self, section_name: &str, data: &[u8]) -> Option<u32> {
        self.try_append_to_section(section_name, data).ok()
    }

    /// Append data to a section, with checked layout and address calculation.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    ///
    /// - No section has the name `section_name`.
    /// - The layout calculation fails.
    /// - The appended data overflows the size or the RVA range of the section.
    pub fn try_append_to_section(&mut self, section_name: &str, data: &[u8]) -> Result<u32> {
        self.try_update_layout()?;
        let section = self
            .sections
            .iter_mut()
            .find(|section| section.name() == section_name)
            .ok_or_else(|| Error::invalid_section(section_name))?;
        let offset = section.try_append_data(data)?;
        let rva = section
            .header
            .virtual_address
            .checked_add(offset)
            .ok_or_else(|| Error::invalid_section("appended section-data RVA overflow"))?;
        self.try_update_layout()?;
        Ok(rva)
    }
}

/// Return the number of bytes at the start of a section that an RVA read can address.
///
/// The loader fills a section with zeros after its raw data. The headers give the end of the
/// section: the larger of `VirtualSize` and `SizeOfRawData`, as in [`Section::contains_rva`].
/// An RVA read uses the same zeros, but only after complete raw data:
///
/// - If the data is shorter than `SizeOfRawData`, the parser could not read some raw bytes (see
///   [`MissingSectionData::Empty`](super::MissingSectionData::Empty)). These bytes are not
///   known to be zero, so the read stops at the end of the data.
/// - The data of a section from a loader-mapped image covers the mapped range. Missing bytes
///   there are also not known to be zero.
///
/// Section data that is longer after an edit stays readable.
fn mapped_extent(section: &Section) -> usize {
    let data_len = section.data.len();
    if section.mapped_raw_size.is_some() || data_len < section.header.size_of_raw_data as usize {
        return data_len;
    }
    (section
        .header
        .virtual_size
        .max(section.header.size_of_raw_data) as usize)
        .max(data_len)
}
