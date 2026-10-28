use super::{HeaderTail, MissingSectionData, ParseOptions, PeHeaders, PeImage, SourceLayout};
use crate::dos::DosHeader;
use crate::layout;
use crate::prelude::*;
use crate::reader::{ReadAt, SliceReader};
use crate::section::Section;
use crate::{Error, Result};

#[cfg(feature = "std")]
use std::path::Path;

impl PeImage {
    /// Create a [`PeBuilder`](crate::PeBuilder) that builds a new PE image from scratch.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use portex::{MachineType, PeImage, Subsystem};
    /// use portex::section::characteristics;
    ///
    /// let pe = PeImage::builder()
    ///     .machine(MachineType::Amd64)
    ///     .subsystem(Subsystem::WindowsCui)
    ///     .add_section(".text", vec![0xCC; 256], characteristics::CODE | characteristics::EXECUTE | characteristics::READ)
    ///     .build();
    /// ```
    #[must_use]
    pub fn builder() -> crate::builder::PeBuilder {
        crate::builder::PeBuilder::new()
    }

    /// Parse the bytes of a PE file from a byte slice.
    ///
    /// The bytes must use the file layout, although they are in memory. For an image that a PE
    /// loader mapped, use [`Self::parse_mapped`].
    ///
    /// # Errors
    ///
    /// Returns an error for any condition listed on [`Self::read_from_with_options`].
    #[must_use = "parsing returns a PE structure that should be used"]
    pub fn parse(data: &[u8]) -> Result<Self> {
        Self::parse_with_layout(data, SourceLayout::File)
    }

    /// Parse a loader-mapped PE image from a byte slice.
    ///
    /// The slice must start at the image base. The parser reads the data of each section at its
    /// RVA, not at its `PointerToRawData` file offset.
    ///
    /// # Errors
    ///
    /// Returns an error for any condition listed on [`Self::read_from_with_options`].
    #[must_use = "parsing returns a PE structure that should be used"]
    pub fn parse_mapped(data: &[u8]) -> Result<Self> {
        Self::parse_with_layout(data, SourceLayout::Mapped)
    }

    /// Parse a loader-mapped image at its actual load base.
    ///
    /// `runtime_image_base` is the VA where the loader mapped the image. It can be different
    /// from `ImageBase` if the loader relocated the image.
    ///
    /// # Errors
    ///
    /// Returns an error for any condition listed on [`Self::read_from_with_options`].
    pub fn parse_mapped_at(data: &[u8], runtime_image_base: u64) -> Result<Self> {
        Self::parse_with_options(
            data,
            ParseOptions::mapped().runtime_image_base(runtime_image_base),
        )
    }

    /// Parse PE bytes with an explicit source layout.
    ///
    /// # Errors
    ///
    /// Returns an error for any condition listed on [`Self::read_from_with_options`].
    #[must_use = "parsing returns a PE structure that should be used"]
    pub fn parse_with_layout(data: &[u8], layout: SourceLayout) -> Result<Self> {
        let reader = SliceReader::new(data);
        Self::read_from(&reader, 0, layout)
    }

    /// Parse PE bytes with explicit [`ParseOptions`] for strictness and source layout.
    ///
    /// # Errors
    ///
    /// Returns an error for any condition listed on [`Self::read_from_with_options`].
    pub fn parse_with_options(data: &[u8], options: ParseOptions) -> Result<Self> {
        let reader = SliceReader::new(data);
        Self::read_from_with_options(&reader, 0, options)
    }

    /// Read a complete PE image from a [`ReadAt`] source with an explicit layout.
    ///
    /// `base_offset` is the offset of the DOS header in the source:
    ///
    /// - For a [`crate::BaseAddressReader`] at a module base, pass `0`. Also use
    ///   [`SourceLayout::Mapped`].
    /// - A remote-process reader can address the whole process. Such a reader can pass the base
    ///   address (a VA) of the module as `base_offset`.
    ///
    /// # Errors
    ///
    /// Returns an error for any condition listed on [`Self::read_from_with_options`].
    #[must_use = "parsing returns a PE structure that should be used"]
    pub fn read_from<R: ReadAt>(
        reader: &R,
        base_offset: u64,
        layout: SourceLayout,
    ) -> Result<Self> {
        Self::read_from_with_options(
            reader,
            base_offset,
            ParseOptions {
                layout,
                missing_section_data: MissingSectionData::Error,
                runtime_image_base: None,
            },
        )
    }

    /// Read a loader-mapped image and keep its actual load base.
    ///
    /// `source_offset` is the offset of the DOS header in the source. `runtime_image_base` is the
    /// VA where the loader mapped the image. The parser uses this base for directories that
    /// contain absolute VAs.
    ///
    /// # Errors
    ///
    /// Returns an error for any condition listed on [`Self::read_from_with_options`].
    pub fn read_mapped_from<R: ReadAt>(
        reader: &R,
        source_offset: u64,
        runtime_image_base: u64,
    ) -> Result<Self> {
        Self::read_from_with_options(
            reader,
            source_offset,
            ParseOptions::mapped().runtime_image_base(runtime_image_base),
        )
    }

    /// Read a complete image with explicit [`ParseOptions`].
    ///
    /// `base_offset` is the offset of the DOS header in the source, as for [`Self::read_from`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - [`PeHeaders::read_from`] fails.
    /// - `e_lfanew` puts the PE header inside the DOS header.
    /// - A section in the file layout has raw bytes but a zero `PointerToRawData`.
    /// - A source offset overflows.
    /// - The reader fails.
    /// - The DOS stub cannot be fully read.
    /// - The bytes of a section cannot be fully read, and the options use
    ///   [`MissingSectionData::Error`].
    pub fn read_from_with_options<R: ReadAt>(
        reader: &R,
        base_offset: u64,
        options: ParseOptions,
    ) -> Result<Self> {
        let headers = PeHeaders::read_from(reader, base_offset)?;
        let header_tail = Self::read_header_tail(reader, base_offset, &headers, options.layout);

        // Read the DOS stub.
        let dos_stub_start = base_offset
            .checked_add(DosHeader::SIZE as u64)
            .ok_or_else(|| Error::invalid_section("DOS stub offset overflow"))?;
        let dos_stub_size = headers
            .pe_offset
            .checked_sub(dos_stub_start)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or_else(|| Error::invalid_section("PE header overlaps the DOS header"))?;
        let dos_stub = if dos_stub_size > 0 {
            Self::read_source_bytes(
                reader,
                dos_stub_start,
                dos_stub_size,
                MissingSectionData::Error,
            )?
        } else {
            Vec::new()
        };

        // Read the section data.
        let mut sections = Vec::with_capacity(headers.section_headers.len());
        for header in headers.section_headers {
            if options.layout == SourceLayout::File
                && header.size_of_raw_data != 0
                && header.pointer_to_raw_data == 0
            {
                return Err(Error::invalid_section(format!(
                    "section '{}' has raw bytes but a zero file pointer",
                    header.name_str()
                )));
            }
            let source_range = match options.layout {
                SourceLayout::File => (header.pointer_to_raw_data != 0
                    && header.size_of_raw_data != 0)
                    .then_some((header.pointer_to_raw_data, header.size_of_raw_data as usize)),
                SourceLayout::Mapped => {
                    let mapped_size = header.virtual_size.max(header.size_of_raw_data);
                    (mapped_size != 0).then_some((header.virtual_address, mapped_size as usize))
                }
            };

            let section_data = match source_range {
                Some((relative_offset, size)) => {
                    let source_offset = base_offset
                        .checked_add(u64::from(relative_offset))
                        .ok_or_else(|| Error::invalid_section("section source offset overflow"))?;
                    Self::read_source_bytes(
                        reader,
                        source_offset,
                        size,
                        options.missing_section_data,
                    )?
                }
                None => Vec::new(),
            };
            sections.push(match options.layout {
                SourceLayout::File => Section::from_header_and_data(header, section_data),
                SourceLayout::Mapped => Section::from_mapped_header_and_data(header, section_data),
            });
        }

        Ok(Self {
            dos_header: headers.dos_header,
            dos_stub,
            coff_header: headers.coff_header,
            optional_header: headers.optional_header,
            sections,
            source_layout: options.layout,
            runtime_image_base: options.runtime_image_base,
            header_tail,
        })
    }

    /// Read the raw header bytes after the section table.
    ///
    /// The bytes end at `SizeOfHeaders`, at the first section and at the end of the source. The
    /// result is empty if the bytes are all zero or cannot be read. The tail is optional data, so
    /// a read failure does not make the parse fail.
    fn read_header_tail<R: ReadAt>(
        reader: &R,
        base_offset: u64,
        headers: &PeHeaders,
        source_layout: SourceLayout,
    ) -> HeaderTail {
        let Some(table_end) = headers
            .pe_offset
            .checked_sub(base_offset)
            .and_then(|pe_offset| usize::try_from(pe_offset).ok())
            .and_then(|pe_offset| {
                layout::headers_size_at(
                    pe_offset,
                    headers.section_headers.len(),
                    usize::from(headers.coff_header.size_of_optional_header),
                )
            })
        else {
            return HeaderTail::default();
        };

        let mut limit = u64::from(headers.optional_header.size_of_headers());
        for header in &headers.section_headers {
            let start = match source_layout {
                SourceLayout::File => (header.pointer_to_raw_data != 0
                    && header.size_of_raw_data != 0)
                    .then_some(header.pointer_to_raw_data),
                SourceLayout::Mapped => (header.virtual_size.max(header.size_of_raw_data) != 0)
                    .then_some(header.virtual_address),
            };
            if let Some(start) = start {
                limit = limit.min(u64::from(start));
            }
        }
        if let Some(source_size) = reader.size() {
            limit = limit.min(source_size.saturating_sub(base_offset));
        }

        let (Some(len), Some(source_offset)) = (
            limit
                .checked_sub(table_end as u64)
                .filter(|len| *len != 0)
                .and_then(|len| usize::try_from(len).ok()),
            base_offset.checked_add(table_end as u64),
        ) else {
            return HeaderTail::default();
        };
        let bytes = Self::read_source_bytes(reader, source_offset, len, MissingSectionData::Empty)
            .unwrap_or_default();
        let mut tail = HeaderTail {
            offset: table_end,
            bytes,
        };
        tail.trim_trailing_zeros();
        tail
    }

    /// Read a source range and apply the selected [`MissingSectionData`] policy.
    fn read_source_bytes<R: ReadAt>(
        reader: &R,
        offset: u64,
        len: usize,
        missing_data: MissingSectionData,
    ) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        let Some(end) = offset.checked_add(len as u64) else {
            return match missing_data {
                MissingSectionData::Error => {
                    Err(Error::invalid_section("section source range overflow"))
                }
                MissingSectionData::Empty => Ok(Vec::new()),
            };
        };
        if reader.size().is_some_and(|source_size| end > source_size) {
            return match missing_data {
                MissingSectionData::Error => Err(Error::buffer_too_small(
                    usize::try_from(end).unwrap_or(usize::MAX),
                    usize::try_from(reader.size().unwrap_or(0)).unwrap_or(usize::MAX),
                )),
                MissingSectionData::Empty => Ok(Vec::new()),
            };
        }

        let mut data = Vec::new();
        data.try_reserve_exact(len)
            .map_err(|_| Error::generic("section source range is too large to allocate"))?;
        data.resize(len, 0);
        let mut total_read = 0usize;
        while total_read < len {
            let read_offset = offset + total_read as u64;
            let count = reader.read_at(read_offset, &mut data[total_read..])?;
            if count == 0 {
                return match missing_data {
                    MissingSectionData::Error => Err(Error::buffer_too_small(len, total_read)),
                    MissingSectionData::Empty => Ok(Vec::new()),
                };
            }
            if count > len - total_read {
                return Err(Error::generic(
                    "ReadAt::read_at reported more bytes than the supplied buffer",
                ));
            }
            total_read += count;
        }
        Ok(data)
    }

    /// Load a PE file from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the read of the file fails. Also returns an error for any condition
    /// listed on [`Self::read_from_with_options`].
    #[cfg(feature = "std")]
    #[must_use = "loading returns a PE structure that should be used"]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::parse(&data)
    }

    /// Read a raw PE image from a sequential `nostdio` stream.
    ///
    /// The normalized image does not keep a file overlay. To keep certificates or other trailing
    /// bytes, use [`crate::PeFile::from_stream`].
    ///
    /// # Errors
    ///
    /// Returns an error if a read from the stream fails. Also returns an error for any condition
    /// listed on [`Self::read_from_with_options`].
    pub fn from_stream<R: nostdio::Read>(stream: &mut R) -> Result<Self> {
        let mut data = Vec::new();
        stream.read_to_end(&mut data)?;
        Self::parse(&data)
    }
}
