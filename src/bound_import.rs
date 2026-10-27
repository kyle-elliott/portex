//! Bound import directory parsing.
//!
//! Bound imports are a legacy optimization: the linker resolves import addresses before load
//! time. If the bound DLL did not change, the loader can skip address resolution.
//!
//! # Examples
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! if let Some(bound) = pe.bound_imports()? {
//!     for desc in &bound.descriptors {
//!         println!("Bound import: {} (timestamp: {:#x})",
//!             desc.module_name, desc.time_date_stamp);
//!         for fwd in &desc.forwarder_refs {
//!             println!("  Forwarder: {} (timestamp: {:#x})",
//!                 fwd.module_name, fwd.time_date_stamp);
//!         }
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```

use crate::prelude::*;
use crate::{Error, Result};

/// A forwarder reference of a bound import (`IMAGE_BOUND_FORWARDER_REF`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundForwarderRef {
    /// Timestamp of the forwarder DLL.
    pub time_date_stamp: u32,
    /// Offset of the module name from the start of the bound import data. This is not an RVA.
    pub offset_module_name: u16,
    /// Reserved.
    pub reserved: u16,
    /// Module name, read from `offset_module_name`.
    pub module_name: String,
}

impl BoundForwarderRef {
    /// Size of the structure in bytes.
    pub const SIZE: usize = 8;

    /// Parse the structure from raw bytes. `module_name` stays empty.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::BufferTooSmall` if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(&[t0, t1, t2, t3, n0, n1, r0, r1]) = data.first_chunk::<8>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };

        Ok(Self {
            time_date_stamp: u32::from_le_bytes([t0, t1, t2, t3]),
            offset_module_name: u16::from_le_bytes([n0, n1]),
            reserved: u16::from_le_bytes([r0, r1]),
            module_name: String::new(), // Resolved later
        })
    }
}

/// A bound import descriptor (`IMAGE_BOUND_IMPORT_DESCRIPTOR`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundImportDescriptor {
    /// Timestamp of the bound DLL.
    pub time_date_stamp: u32,
    /// Offset of the module name from the start of the bound import data. This is not an RVA.
    pub offset_module_name: u16,
    /// Number of forwarder references.
    pub number_of_module_forwarder_refs: u16,
    /// Module name, read from `offset_module_name`.
    pub module_name: String,
    /// Forwarder references.
    pub forwarder_refs: Vec<BoundForwarderRef>,
}

impl BoundImportDescriptor {
    /// Size of the structure in bytes.
    pub const SIZE: usize = 8;

    /// Parse the structure from raw bytes. Returns `None` for the null terminator.
    ///
    /// `module_name` and `forwarder_refs` stay empty.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::BufferTooSmall` if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Option<Self>> {
        let Some(&[t0, t1, t2, t3, n0, n1, c0, c1]) = data.first_chunk::<8>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };

        let time_date_stamp = u32::from_le_bytes([t0, t1, t2, t3]);
        let offset_module_name = u16::from_le_bytes([n0, n1]);
        let number_of_module_forwarder_refs = u16::from_le_bytes([c0, c1]);

        // Check for the null terminator.
        if time_date_stamp == 0 && offset_module_name == 0 && number_of_module_forwarder_refs == 0 {
            return Ok(None);
        }

        Ok(Some(Self {
            time_date_stamp,
            offset_module_name,
            number_of_module_forwarder_refs,
            module_name: String::new(), // Resolved later
            forwarder_refs: Vec::new(), // Parsed later
        }))
    }
}

/// Bound import directory: the data of the `BoundImport` data directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoundImportDirectory {
    /// List of bound import descriptors.
    pub descriptors: Vec<BoundImportDescriptor>,
}

impl BoundImportDirectory {
    /// Parse the bound import directory from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data-directory error in these conditions:
    ///
    /// - A descriptor or forwarder record is truncated.
    /// - A module-name offset is zero or out of range.
    /// - A name is not null-terminated.
    /// - The reserved field of a forwarder is not zero.
    /// - The directory has no null terminator.
    ///
    /// Returns an invalid-UTF-8 error if a module name is not valid UTF-8.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut descriptors = Vec::new();
        let mut offset = 0;

        // Parse each descriptor and the forwarder records that immediately follow it.
        while offset < data.len() {
            let descriptor_end = offset
                .checked_add(BoundImportDescriptor::SIZE)
                .ok_or_else(|| Error::invalid_data_directory("bound-import offset overflow"))?;
            let descriptor_bytes = data.get(offset..descriptor_end).ok_or_else(|| {
                Error::invalid_data_directory("truncated bound-import descriptor")
            })?;
            match BoundImportDescriptor::parse(descriptor_bytes)? {
                Some(mut desc) => {
                    if desc.offset_module_name == 0 {
                        return Err(Error::invalid_data_directory(
                            "bound-import descriptor has a zero module-name offset",
                        ));
                    }
                    // Read the module name.
                    let name_offset = usize::from(desc.offset_module_name);
                    desc.module_name = read_cstring(data.get(name_offset..).ok_or_else(|| {
                        Error::invalid_data_directory("bound-import module name is out of range")
                    })?)?;

                    // Parse the forwarder references.
                    let fwd_start = descriptor_end;
                    for i in 0..usize::from(desc.number_of_module_forwarder_refs) {
                        let relative = i.checked_mul(BoundForwarderRef::SIZE).ok_or_else(|| {
                            Error::invalid_data_directory("bound-forwarder size overflow")
                        })?;
                        let fwd_offset = fwd_start.checked_add(relative).ok_or_else(|| {
                            Error::invalid_data_directory("bound-forwarder offset overflow")
                        })?;
                        let fwd_end =
                            fwd_offset
                                .checked_add(BoundForwarderRef::SIZE)
                                .ok_or_else(|| {
                                    Error::invalid_data_directory("bound-forwarder range overflow")
                                })?;
                        let mut fwd = BoundForwarderRef::parse(
                            data.get(fwd_offset..fwd_end).ok_or_else(|| {
                                Error::invalid_data_directory("truncated bound-forwarder record")
                            })?,
                        )?;
                        if fwd.reserved != 0 {
                            return Err(Error::invalid_data_directory(
                                "bound-forwarder reserved field must be zero",
                            ));
                        }
                        if fwd.offset_module_name == 0 {
                            return Err(Error::invalid_data_directory(
                                "bound-forwarder has a zero module-name offset",
                            ));
                        }
                        let fwd_name_offset = usize::from(fwd.offset_module_name);
                        fwd.module_name =
                            read_cstring(data.get(fwd_name_offset..).ok_or_else(|| {
                                Error::invalid_data_directory(
                                    "bound-forwarder module name is out of range",
                                )
                            })?)?;
                        desc.forwarder_refs.push(fwd);
                    }

                    // Skip past the descriptor and its forwarder references.
                    offset = fwd_start
                        .checked_add(
                            usize::from(desc.number_of_module_forwarder_refs)
                                .checked_mul(BoundForwarderRef::SIZE)
                                .ok_or_else(|| {
                                    Error::invalid_data_directory("bound-forwarder size overflow")
                                })?,
                        )
                        .ok_or_else(|| {
                            Error::invalid_data_directory("bound-import offset overflow")
                        })?;
                    descriptors.push(desc);
                }
                None => return Ok(Self { descriptors }),
            }
        }

        Err(Error::invalid_data_directory(
            "bound-import directory is missing a terminator",
        ))
    }
}

/// Read a null-terminated C string from a byte slice.
fn read_cstring(data: &[u8]) -> Result<String> {
    let name = core::ffi::CStr::from_bytes_until_nul(data)
        .map_err(|_| Error::invalid_data_directory("bound-import name is not null-terminated"))?;
    name.to_str()
        .map(String::from)
        .map_err(|_| Error::invalid_utf8())
}

/// Builder that serializes bound import directories.
#[derive(Debug, Default)]
pub struct BoundImportBuilder;

impl BoundImportBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Calculate the total size needed for the bound import data.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_calculate_size`] fails.
    #[must_use]
    pub fn calculate_size(directory: &BoundImportDirectory) -> usize {
        Self::try_calculate_size(directory)
            .expect("bound-import size overflow: use try_calculate_size()")
    }

    /// Calculate the size, and validate the 16-bit name offsets and forwarder counts.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data-directory error in these conditions:
    ///
    /// - A descriptor has more than `u16::MAX` forwarders.
    /// - The reserved field of a forwarder is not zero.
    /// - A module name is empty or contains NUL.
    /// - The size overflows.
    /// - The total is more than `u16::MAX` (the limit of the 16-bit name offsets).
    pub fn try_calculate_size(directory: &BoundImportDirectory) -> Result<usize> {
        if directory.descriptors.is_empty() {
            return Ok(0);
        }

        // Descriptors, forwarder references and the null terminator.
        let mut desc_size = BoundImportDescriptor::SIZE; // null terminator
        for desc in &directory.descriptors {
            u16::try_from(desc.forwarder_refs.len())
                .map_err(|_| Error::invalid_data_directory("bound-forwarder count exceeds u16"))?;
            if desc
                .forwarder_refs
                .iter()
                .any(|forwarder| forwarder.reserved != 0)
            {
                return Err(Error::invalid_data_directory(
                    "bound-forwarder reserved field must be zero",
                ));
            }
            desc_size = desc_size
                .checked_add(BoundImportDescriptor::SIZE)
                .and_then(|size| {
                    desc.forwarder_refs
                        .len()
                        .checked_mul(BoundForwarderRef::SIZE)
                        .and_then(|forwarders| size.checked_add(forwarders))
                })
                .ok_or_else(|| {
                    Error::invalid_data_directory("bound-import descriptor size overflow")
                })?;
        }

        // Module names (null-terminated strings).
        let mut names_size = 0usize;
        for desc in &directory.descriptors {
            names_size = checked_bound_name_size(names_size, &desc.module_name)?;
            for fwd in &desc.forwarder_refs {
                names_size = checked_bound_name_size(names_size, &fwd.module_name)?;
            }
        }

        let total = desc_size
            .checked_add(names_size)
            .ok_or_else(|| Error::invalid_data_directory("bound-import size overflow"))?;
        if total > usize::from(u16::MAX) {
            return Err(Error::invalid_data_directory(
                "bound-import directory exceeds its u16 name-offset format",
            ));
        }
        Ok(total)
    }

    /// Build the bound import data. Returns `(data, size)`.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] fails.
    #[must_use]
    pub fn build(directory: &BoundImportDirectory) -> (Vec<u8>, u32) {
        Self::try_build(directory)
            .expect("bound-import build failed: use try_build() for fallible serialization")
    }

    /// Build the bound import data, with checked relative offsets. Returns `(data, size)`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::try_calculate_size`]. Returns an invalid-data-directory
    /// error if the data size is more than `u32::MAX` or a name offset is more than `u16::MAX`.
    pub fn try_build(directory: &BoundImportDirectory) -> Result<(Vec<u8>, u32)> {
        if directory.descriptors.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let total_size = Self::try_calculate_size(directory)?;
        let total_size_u32 = u32::try_from(total_size)
            .map_err(|_| Error::invalid_data_directory("bound-import data exceeds u32"))?;

        // The descriptors, the forwarder records and the null terminator come before the names.
        let strings_offset = directory
            .descriptors
            .iter()
            .try_fold(BoundImportDescriptor::SIZE, |size, desc| {
                desc.forwarder_refs
                    .len()
                    .checked_add(1)?
                    .checked_mul(BoundImportDescriptor::SIZE)
                    .and_then(|records| size.checked_add(records))
            })
            .ok_or_else(|| {
                Error::invalid_data_directory("bound-import descriptor size overflow")
            })?;
        // Each name offset is relative to the start of the bound import data.
        let next_name_offset = |names: &[u8]| {
            strings_offset
                .checked_add(names.len())
                .and_then(|offset| u16::try_from(offset).ok())
        };

        let mut data = Vec::with_capacity(total_size);
        let mut names = Vec::new();
        for desc in &directory.descriptors {
            let name_offset = next_name_offset(&names).ok_or_else(|| {
                Error::invalid_data_directory("bound-import name offset exceeds u16")
            })?;
            let forwarder_count = u16::try_from(desc.forwarder_refs.len())
                .map_err(|_| Error::invalid_data_directory("bound-forwarder count exceeds u16"))?;
            data.extend_from_slice(&desc.time_date_stamp.to_le_bytes());
            data.extend_from_slice(&name_offset.to_le_bytes());
            data.extend_from_slice(&forwarder_count.to_le_bytes());
            names.extend_from_slice(desc.module_name.as_bytes());
            names.push(0);

            for fwd in &desc.forwarder_refs {
                let fwd_name_offset = next_name_offset(&names).ok_or_else(|| {
                    Error::invalid_data_directory("bound-forwarder name offset exceeds u16")
                })?;
                data.extend_from_slice(&fwd.time_date_stamp.to_le_bytes());
                data.extend_from_slice(&fwd_name_offset.to_le_bytes());
                data.extend_from_slice(&fwd.reserved.to_le_bytes());
                names.extend_from_slice(fwd.module_name.as_bytes());
                names.push(0);
            }
        }

        // Add the null terminator descriptor, then the names.
        data.extend_from_slice(&[0; BoundImportDescriptor::SIZE]);
        data.extend_from_slice(&names);

        Ok((data, total_size_u32))
    }
}

fn checked_bound_name_size(current: usize, name: &str) -> Result<usize> {
    if name.is_empty() || name.as_bytes().contains(&0) {
        return Err(Error::invalid_data_directory(
            "bound-import module names must be nonempty and contain no NUL bytes",
        ));
    }
    current
        .checked_add(
            name.len()
                .checked_add(1)
                .ok_or_else(|| Error::invalid_data_directory("bound-import name size overflow"))?,
        )
        .ok_or_else(|| Error::invalid_data_directory("bound-import names size overflow"))
}

#[cfg(test)]
mod tests {
    use super::{
        BoundForwarderRef, BoundImportBuilder, BoundImportDescriptor, BoundImportDirectory,
    };
    use crate::prelude::{ToString, Vec, vec};

    #[test]
    fn test_bound_import_descriptor_size() {
        assert_eq!(BoundImportDescriptor::SIZE, 8);
    }

    #[test]
    fn test_bound_forwarder_ref_size() {
        assert_eq!(BoundForwarderRef::SIZE, 8);
    }

    #[test]
    fn test_null_terminator() {
        let data = [0u8; 8];
        let desc = BoundImportDescriptor::parse(&data).unwrap();
        assert!(desc.is_none());
    }

    #[test]
    fn test_buffer_too_small() {
        let data = [0u8; 7];
        assert!(BoundImportDescriptor::parse(&data).is_err());
    }

    #[test]
    fn test_builder_empty() {
        let dir = BoundImportDirectory::default();
        let (data, size) = BoundImportBuilder::build(&dir);
        assert_eq!(data, Vec::<u8>::new());
        assert_eq!(size, 0);
    }

    #[test]
    fn test_builder_roundtrip() {
        let dir = BoundImportDirectory {
            descriptors: vec![BoundImportDescriptor {
                time_date_stamp: 0x1234_5678,
                offset_module_name: 0,
                number_of_module_forwarder_refs: 0,
                module_name: "kernel32.dll".to_string(),
                forwarder_refs: vec![],
            }],
        };

        let (data, _size) = BoundImportBuilder::build(&dir);

        // Parse it back
        let parsed = BoundImportDirectory::parse(&data).unwrap();
        assert_eq!(parsed.descriptors.len(), 1);
        assert_eq!(parsed.descriptors[0].module_name, "kernel32.dll");
        assert_eq!(parsed.descriptors[0].time_date_stamp, 0x1234_5678);
    }

    #[test]
    fn test_builder_layout_with_forwarders() {
        let descriptor = |time_date_stamp, name: &str, forwarder_refs| BoundImportDescriptor {
            time_date_stamp,
            offset_module_name: 0,
            number_of_module_forwarder_refs: 0,
            module_name: name.to_string(),
            forwarder_refs,
        };
        let forwarder = BoundForwarderRef {
            time_date_stamp: 2,
            offset_module_name: 0,
            reserved: 0,
            module_name: "b.dll".to_string(),
        };
        let dir = BoundImportDirectory {
            descriptors: vec![
                descriptor(1, "a.dll", vec![forwarder]),
                descriptor(3, "c.dll", vec![]),
            ],
        };

        let (data, size) = BoundImportBuilder::try_build(&dir).unwrap();
        // Four 8-byte records (with the terminator), then three 6-byte names.
        assert_eq!(data.len(), 50);
        assert_eq!(size, 50);
        assert_eq!(BoundImportBuilder::try_calculate_size(&dir).unwrap(), 50);
        assert_eq!(data[0..8], [1, 0, 0, 0, 32, 0, 1, 0]);
        assert_eq!(data[8..16], [2, 0, 0, 0, 38, 0, 0, 0]);
        assert_eq!(data[16..24], [3, 0, 0, 0, 44, 0, 0, 0]);
        assert_eq!(data[24..32], [0; 8]);
        assert_eq!(&data[32..], b"a.dll\0b.dll\0c.dll\0");

        let parsed = BoundImportDirectory::parse(&data).unwrap();
        assert_eq!(parsed.descriptors.len(), 2);
        assert_eq!(parsed.descriptors[0].forwarder_refs[0].module_name, "b.dll");
        assert_eq!(parsed.descriptors[1].module_name, "c.dll");
    }

    #[test]
    fn test_parse_rejects_bad_names() {
        // The name at offset 16 has no null terminator.
        let mut data = vec![1, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'a'];
        assert!(BoundImportDirectory::parse(&data).is_err());
        // The name offset is past the end of the data.
        data[4] = 0x40;
        assert!(BoundImportDirectory::parse(&data).is_err());
        // A truncated descriptor.
        assert!(BoundImportDirectory::parse(&data[..4]).is_err());
    }
}
