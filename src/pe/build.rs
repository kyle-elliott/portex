use super::PeImage;
use crate::coff::{CoffHeader, PE_SIGNATURE};
use crate::dos::DosHeader;
use crate::prelude::*;
use crate::section::SectionHeader;
use crate::{Error, Result};

#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::path::Path;

impl PeImage {
    /// Build the PE file as a byte vector.
    ///
    /// This method does not change `self`. It computes the layout on a clone.
    ///
    /// For untrusted or hand-built structures, use [`Self::try_build`]. It returns an error for a
    /// structural problem and does not panic.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] returns an error.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        self.try_build()
            .expect("PE build failed: use PeImage::try_build() to handle invalid structures")
    }

    /// Build the PE file, or return an error for an invalid offset, size or header relationship.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The layout update fails.
    /// - `e_lfanew`, the DOS stub, the optional header or the raw ranges of the sections are not
    ///   consistent, or they overflow.
    /// - The `PointerToRawData` file offset of a debug directory entry cannot be rebased.
    /// - The allocation of the output buffer fails.
    pub fn try_build(&self) -> Result<Vec<u8>> {
        let mut pe = self.clone();
        pe.try_update_layout()?;
        pe.synchronize_file_offsets()?;
        pe.try_write_bytes()
    }

    /// Serialize the image with the current raw file offsets, and do not recompute the layout.
    ///
    /// [`crate::PeFile`] uses this method to keep intentional file gaps when the parsed layout
    /// does not change otherwise.
    pub(crate) fn try_build_current_layout(&self) -> Result<Vec<u8>> {
        if !self.current_layout_can_hold_data()? {
            return Err(Error::invalid_section(
                "current raw layout cannot hold the edited section data",
            ));
        }
        let mut pe = self.clone();
        pe.synchronize_file_offsets()?;
        pe.try_write_bytes()
    }

    pub(crate) fn current_layout_can_hold_data(&self) -> Result<bool> {
        let Ok(headers) = self.build_headers() else {
            return Ok(false);
        };
        let header_limit = self.optional_header.size_of_headers() as usize;
        if headers.len() > header_limit {
            return Ok(false);
        }

        let mut ranges = Vec::with_capacity(self.sections.len());
        for section in &self.sections {
            let start = section.header.pointer_to_raw_data as usize;
            let size = section.header.size_of_raw_data as usize;
            if size == 0 {
                if !section.data.is_empty() && section.preserved_raw_size() != Some(0) {
                    return Ok(false);
                }
                continue;
            }
            if start < header_limit || section.data.len() > size {
                return Ok(false);
            }
            let end = start
                .checked_add(size)
                .ok_or_else(|| Error::invalid_section("section file range overflow"))?;
            ranges.push(start..end);
        }
        ranges.sort_by_key(|range| range.start);
        Ok(ranges.windows(2).all(|pair| pair[0].end <= pair[1].start))
    }

    /// Make a loader-style memory image of this normalized image at its current runtime base.
    ///
    /// # Errors
    ///
    /// Returns an error for the same conditions as [`Self::to_mapped_image_at`].
    pub fn to_mapped_image(&self) -> Result<Vec<u8>> {
        self.to_mapped_image_at(self.runtime_image_base())
    }

    /// Make a loader-style memory image at `runtime_image_base`.
    ///
    /// `runtime_image_base` is the VA of the image in memory. If it is different from the current
    /// base of the bytes, the method applies the base relocation table.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The layout update or the header serialization fails.
    /// - A section extends past `SizeOfImage`.
    /// - The allocation of the image buffer fails.
    /// - A rebase is necessary, but the base relocation table is missing or malformed, or it
    ///   targets bytes outside the image.
    pub fn to_mapped_image_at(&self, runtime_image_base: u64) -> Result<Vec<u8>> {
        let mut pe = self.clone();
        pe.try_update_layout()?;
        let image_size = pe.optional_header.size_of_image() as usize;
        let mut mapped = try_zeroed_buffer(image_size, "mapped image")?;

        let headers = pe.build_headers()?;
        let header_count = headers
            .len()
            .min(pe.optional_header.size_of_headers() as usize)
            .min(mapped.len());
        mapped[..header_count].copy_from_slice(&headers[..header_count]);

        for section in &pe.sections {
            let start = section.header.virtual_address as usize;
            let mapped_size = section
                .header
                .virtual_size
                .max(section.header.size_of_raw_data) as usize;
            let end = start
                .checked_add(mapped_size)
                .ok_or_else(|| Error::invalid_section("mapped section range overflow"))?;
            if end > mapped.len() {
                return Err(Error::invalid_section(format!(
                    "section '{}' exceeds SizeOfImage",
                    section.name()
                )));
            }
            let count = section.data.len().min(mapped_size);
            mapped[start..start + count].copy_from_slice(&section.data[..count]);
        }

        let current_base = pe.runtime_image_base();
        if runtime_image_base != current_base {
            let relocations = pe.relocations()?;
            if relocations.is_empty() {
                return Err(Error::invalid_data_directory(format!(
                    "cannot move image from {current_base:#x} to {runtime_image_base:#x} without base relocations"
                )));
            }
            let delta = i128::from(runtime_image_base) - i128::from(current_base);
            relocations.try_apply(&mut mapped, delta, pe.is_64bit())?;
        }

        Ok(mapped)
    }

    /// Update the pointer fields that hold raw file offsets after a change to the section layout.
    fn synchronize_file_offsets(&mut self) -> Result<()> {
        use crate::data_dir::DataDirectoryType;
        use crate::debug::DebugDirectory;

        let Some(directory) = self
            .data_directory(DataDirectoryType::Debug)
            .copied()
            .filter(|dir| dir.is_present())
        else {
            return Ok(());
        };
        if !(directory.size as usize).is_multiple_of(DebugDirectory::SIZE) {
            return Err(Error::invalid_data_directory(format!(
                "debug directory size {} is not a multiple of {}",
                directory.size,
                DebugDirectory::SIZE
            )));
        }

        let count = directory.size as usize / DebugDirectory::SIZE;
        for index in 0..count {
            let relative = index
                .checked_mul(DebugDirectory::SIZE)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| Error::invalid_data_directory("debug table offset overflow"))?;
            let entry_rva = directory
                .virtual_address
                .checked_add(relative)
                .ok_or_else(|| Error::invalid_data_directory("debug directory RVA overflow"))?;
            let bytes = self
                .read_rva(entry_rva, DebugDirectory::SIZE)
                .ok_or_else(|| Error::invalid_rva(entry_rva))?;
            let entry = DebugDirectory::parse(&bytes)?;
            if entry.address_of_raw_data == 0 {
                continue;
            }
            let file_offset = self
                .rva_to_offset(entry.address_of_raw_data)
                .ok_or_else(|| {
                    Error::invalid_data_directory(format!(
                        "debug payload RVA {:#x} has no raw-file offset",
                        entry.address_of_raw_data
                    ))
                })?;
            let field_rva = entry_rva
                .checked_add(24)
                .ok_or_else(|| Error::invalid_data_directory("debug pointer RVA overflow"))?;
            self.write_at_rva(field_rva, &file_offset.to_le_bytes())
                .ok_or_else(|| Error::invalid_rva(field_rva))?;
        }
        Ok(())
    }

    pub(super) fn build_headers(&self) -> Result<Vec<u8>> {
        let pe_offset = usize::try_from(self.dos_header.e_lfanew).map_err(|_| {
            Error::invalid_section("e_lfanew is negative and cannot locate a PE header")
        })?;
        if pe_offset < DosHeader::SIZE {
            return Err(Error::invalid_section(
                "e_lfanew places the PE header inside the DOS header",
            ));
        }

        let stub_end = DosHeader::SIZE
            .checked_add(self.dos_stub.len())
            .ok_or_else(|| Error::invalid_section("DOS stub size overflow"))?;
        if stub_end > pe_offset {
            return Err(Error::invalid_section(format!(
                "DOS stub ends at {stub_end:#x}, after e_lfanew {pe_offset:#x}"
            )));
        }

        let coff_offset = pe_offset
            .checked_add(4)
            .ok_or_else(|| Error::invalid_section("COFF header offset overflow"))?;
        let optional_offset = coff_offset
            .checked_add(CoffHeader::SIZE)
            .ok_or_else(|| Error::invalid_section("optional-header offset overflow"))?;
        let optional_size = self.optional_header.size();
        let declared_optional_size = usize::from(self.coff_header.size_of_optional_header);
        if optional_size > declared_optional_size {
            return Err(Error::invalid_section(format!(
                "optional header needs {optional_size} bytes, but COFF declares {declared_optional_size}"
            )));
        }
        let sections_offset = optional_offset
            .checked_add(declared_optional_size)
            .ok_or_else(|| Error::invalid_section("section-table offset overflow"))?;
        let section_table_size = self
            .sections
            .len()
            .checked_mul(SectionHeader::SIZE)
            .ok_or_else(|| Error::invalid_section("section-table size overflow"))?;
        let header_end = sections_offset
            .checked_add(section_table_size)
            .ok_or_else(|| Error::invalid_section("header size overflow"))?;

        // Each range below ends at or before `header_end`, which is `output.len()`.
        let mut output = try_zeroed_buffer(header_end, "PE headers")?;
        self.dos_header.write(&mut output[..DosHeader::SIZE])?;
        output[DosHeader::SIZE..stub_end].copy_from_slice(&self.dos_stub);
        output[pe_offset..coff_offset].copy_from_slice(&PE_SIGNATURE.to_le_bytes());
        self.coff_header
            .write(&mut output[coff_offset..optional_offset])?;
        self.optional_header
            .write(&mut output[optional_offset..sections_offset])?;

        let (section_table, _) =
            output[sections_offset..].as_chunks_mut::<{ SectionHeader::SIZE }>();
        for (section, slot) in self.sections.iter().zip(section_table) {
            section.header.write(slot)?;
        }

        Ok(output)
    }

    /// Write the PE bytes, and do not update the layout.
    ///
    /// Use this method after a call to `update_layout()` to prevent repeated work.
    fn try_write_bytes(&self) -> Result<Vec<u8>> {
        // Calculate the total file size.
        let mut file_size = self.optional_header.size_of_headers() as usize;
        for section in &self.sections {
            if section.header.pointer_to_raw_data > 0 {
                let end = (section.header.pointer_to_raw_data as usize)
                    .checked_add(section.header.size_of_raw_data as usize)
                    .ok_or_else(|| Error::invalid_section("section file range overflow"))?;
                file_size = file_size.max(end);
            }
        }

        let headers = self.build_headers()?;
        file_size = file_size.max(headers.len());
        let mut output = try_zeroed_buffer(file_size, "raw PE image")?;
        output[..headers.len()].copy_from_slice(&headers);

        if usize::from(self.coff_header.number_of_sections) != self.sections.len() {
            return Err(Error::invalid_section(format!(
                "COFF declares {} sections, but {} section records are present",
                self.coff_header.number_of_sections,
                self.sections.len()
            )));
        }

        // Write the section data.
        for section in &self.sections {
            let start = section.header.pointer_to_raw_data as usize;
            let aligned_size = section.header.size_of_raw_data as usize;
            let end = start
                .checked_add(aligned_size)
                .ok_or_else(|| Error::invalid_section("section file range overflow"))?;
            if start > 0 && aligned_size > 0 && end <= output.len() {
                let data_len = section.data.len().min(aligned_size);
                output[start..start + data_len].copy_from_slice(&section.data[..data_len]);
                // The padding is already zero.
            } else if !section.data.is_empty() && section.preserved_raw_size() != Some(0) {
                return Err(Error::invalid_section(format!(
                    "section '{}' has data but no writable raw-file range",
                    section.name()
                )));
            }
        }

        Ok(output)
    }

    /// Write the PE file to disk.
    ///
    /// This method does not change `self`. It computes the layout on a clone.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::try_build`] fails, or if the creation of the file or the write
    /// fails.
    #[cfg(feature = "std")]
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.write_to(&mut File::create(path)?)
    }

    /// Serialize this normalized image to a `nostdio` stream.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::try_build`] fails or the stream write fails.
    pub fn write_to<W: nostdio::Write>(&self, stream: &mut W) -> Result<()> {
        stream.write_all(&self.try_build()?)?;
        Ok(())
    }
}

fn try_zeroed_buffer(size: usize, context: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| Error::generic(format!("{context} is too large to allocate")))?;
    bytes.resize(size, 0);
    Ok(bytes)
}
