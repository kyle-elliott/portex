//! Resource directory parsing and building.
//!
//! The resource directory contains embedded resources like icons, version info,
//! manifests, dialogs, and other application data.
//!
//! # Examples
//!
//! ## Listing resources from a PE file
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! let resources = pe.resources()?;
//! for resource in &resources.resources {
//!     println!("Type: {:?}, Name: {:?}, Language: {}, Size: {}",
//!         resource.type_id,
//!         resource.name,
//!         resource.language,
//!         resource.size);
//! }
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Adding resources to a PE file
//!
//! ```no_run
//! use portex::{PeImage, ResourceBuilder, ResourceType};
//!
//! # let file_bytes: &[u8] = &[];
//! let mut pe = PeImage::parse(file_bytes)?;
//!
//! // Build resources
//! let mut builder = ResourceBuilder::new();
//!
//! // Add a manifest (RT_MANIFEST = 24)
//! let manifest = b"<?xml version=\"1.0\"?>...";
//! builder.add_resource(ResourceType::Manifest, 1, 0x0409, manifest.to_vec());
//!
//! // Add an icon
//! let icon_data = vec![0u8; 16];
//! builder.add_resource(ResourceType::Icon, 1, 0x0409, icon_data);
//!
//! // Update PE with new resources (using builder for new resources)
//! pe.update_resources_from_builder(&builder, None)?;
//! let rebuilt = pe.try_build()?;
//! assert!(!rebuilt.is_empty());
//! # Ok::<(), portex::Error>(())
//! ```

use crate::prelude::*;
use crate::{Error, Result};

/// Standard resource types (`RT_*` values used as level-1 IDs of the resource tree).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ResourceType {
    /// `RT_CURSOR` (1): hardware-dependent cursor image.
    Cursor = 1,
    /// `RT_BITMAP` (2): bitmap image.
    Bitmap = 2,
    /// `RT_ICON` (3): hardware-dependent icon image.
    Icon = 3,
    /// `RT_MENU` (4): menu template.
    Menu = 4,
    /// `RT_DIALOG` (5): dialog box template.
    Dialog = 5,
    /// `RT_STRING` (6): string-table block of 16 strings.
    String = 6,
    /// `RT_FONTDIR` (7): font directory.
    FontDir = 7,
    /// `RT_FONT` (8): font.
    Font = 8,
    /// `RT_ACCELERATOR` (9): accelerator table.
    Accelerator = 9,
    /// `RT_RCDATA` (10): application-defined raw data.
    RcData = 10,
    /// `RT_MESSAGETABLE` (11): message-table entry.
    MessageTable = 11,
    /// `RT_GROUP_CURSOR` (12): hardware-independent cursor group.
    GroupCursor = 12,
    /// `RT_GROUP_ICON` (14): hardware-independent icon group.
    GroupIcon = 14,
    /// `RT_VERSION` (16): version information (`VS_VERSIONINFO`).
    Version = 16,
    /// `RT_DLGINCLUDE` (17): name of a header file for a dialog template.
    DlgInclude = 17,
    /// `RT_PLUGPLAY` (19): Plug and Play resource.
    PlugPlay = 19,
    /// `RT_VXD` (20): `VxD` resource.
    Vxd = 20,
    /// `RT_ANICURSOR` (21): animated cursor.
    AniCursor = 21,
    /// `RT_ANIICON` (22): animated icon.
    AniIcon = 22,
    /// `RT_HTML` (23): HTML document.
    Html = 23,
    /// `RT_MANIFEST` (24): side-by-side assembly manifest.
    Manifest = 24,
}

impl ResourceType {
    /// Convert a numeric `RT_*` value to a standard resource type.
    ///
    /// Returns `None` for values that are not standard resource types.
    #[must_use]
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Cursor),
            2 => Some(Self::Bitmap),
            3 => Some(Self::Icon),
            4 => Some(Self::Menu),
            5 => Some(Self::Dialog),
            6 => Some(Self::String),
            7 => Some(Self::FontDir),
            8 => Some(Self::Font),
            9 => Some(Self::Accelerator),
            10 => Some(Self::RcData),
            11 => Some(Self::MessageTable),
            12 => Some(Self::GroupCursor),
            14 => Some(Self::GroupIcon),
            16 => Some(Self::Version),
            17 => Some(Self::DlgInclude),
            19 => Some(Self::PlugPlay),
            20 => Some(Self::Vxd),
            21 => Some(Self::AniCursor),
            22 => Some(Self::AniIcon),
            23 => Some(Self::Html),
            24 => Some(Self::Manifest),
            _ => None,
        }
    }

    /// Upper-case type name without the `RT_` prefix (e.g. `"MANIFEST"`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Cursor => "CURSOR",
            Self::Bitmap => "BITMAP",
            Self::Icon => "ICON",
            Self::Menu => "MENU",
            Self::Dialog => "DIALOG",
            Self::String => "STRING",
            Self::FontDir => "FONTDIR",
            Self::Font => "FONT",
            Self::Accelerator => "ACCELERATOR",
            Self::RcData => "RCDATA",
            Self::MessageTable => "MESSAGETABLE",
            Self::GroupCursor => "GROUP_CURSOR",
            Self::GroupIcon => "GROUP_ICON",
            Self::Version => "VERSION",
            Self::DlgInclude => "DLGINCLUDE",
            Self::PlugPlay => "PLUGPLAY",
            Self::Vxd => "VXD",
            Self::AniCursor => "ANICURSOR",
            Self::AniIcon => "ANIICON",
            Self::Html => "HTML",
            Self::Manifest => "MANIFEST",
        }
    }
}

/// Resource name/ID - can be numeric or string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceId {
    /// Numeric ID.
    Id(u16),
    /// String name.
    Name(String),
}

impl ResourceId {
    /// Check if this is a standard resource type ID.
    #[must_use]
    pub fn as_resource_type(&self) -> Option<ResourceType> {
        match self {
            Self::Id(id) => ResourceType::from_u16(*id),
            Self::Name(_) => None,
        }
    }
}

/// `IMAGE_RESOURCE_DIRECTORY` (16 bytes): header of one level of the resource
/// tree, followed by its named entries and then its ID entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceDirectoryHeader {
    /// Resource flags (reserved, usually 0).
    pub characteristics: u32,
    /// Time/date stamp.
    pub time_date_stamp: u32,
    /// Major version.
    pub major_version: u16,
    /// Minor version.
    pub minor_version: u16,
    /// Number of named entries.
    pub number_of_named_entries: u16,
    /// Number of ID entries.
    pub number_of_id_entries: u16,
}

impl ResourceDirectoryHeader {
    /// Size of `IMAGE_RESOURCE_DIRECTORY` in bytes.
    pub const SIZE: usize = 16;

    /// Parse an `IMAGE_RESOURCE_DIRECTORY` from little-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns a buffer-too-small error if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }

        Ok(Self {
            characteristics: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            time_date_stamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            major_version: u16::from_le_bytes([data[8], data[9]]),
            minor_version: u16::from_le_bytes([data[10], data[11]]),
            number_of_named_entries: u16::from_le_bytes([data[12], data[13]]),
            number_of_id_entries: u16::from_le_bytes([data[14], data[15]]),
        })
    }

    /// Serialize to the little-endian on-disk layout.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.characteristics.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..10].copy_from_slice(&self.major_version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.minor_version.to_le_bytes());
        buf[12..14].copy_from_slice(&self.number_of_named_entries.to_le_bytes());
        buf[14..16].copy_from_slice(&self.number_of_id_entries.to_le_bytes());
        buf
    }

    /// Total number of directory entries (named plus ID) following the header.
    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.number_of_named_entries as usize + self.number_of_id_entries as usize
    }
}

/// `IMAGE_RESOURCE_DIRECTORY_ENTRY` (8 bytes): one entry of a resource
/// directory, naming a child and pointing to a subdirectory or data entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceDirectoryEntry {
    /// Name offset (high bit set) or ID.
    pub name_or_id: u32,
    /// Offset to data or subdirectory (high bit set = subdirectory).
    pub offset_to_data: u32,
}

impl ResourceDirectoryEntry {
    /// Size of `IMAGE_RESOURCE_DIRECTORY_ENTRY` in bytes.
    pub const SIZE: usize = 8;

    /// Parse an `IMAGE_RESOURCE_DIRECTORY_ENTRY` from little-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns a buffer-too-small error if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }

        Ok(Self {
            name_or_id: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            offset_to_data: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        })
    }

    /// Serialize to the little-endian on-disk layout.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.name_or_id.to_le_bytes());
        buf[4..8].copy_from_slice(&self.offset_to_data.to_le_bytes());
        buf
    }

    /// Check if this entry has a string name (vs numeric ID).
    #[must_use]
    pub fn is_named(self) -> bool {
        (self.name_or_id & 0x8000_0000) != 0
    }

    /// Get the name offset, relative to the start of the resource directory
    /// (only valid if [`Self::is_named`] is true).
    #[must_use]
    pub fn name_offset(self) -> u32 {
        self.name_or_id & 0x7FFF_FFFF
    }

    /// Get the ID from the low 16 bits (only valid if [`Self::is_named`] is false).
    #[must_use]
    pub fn id(self) -> u16 {
        (self.name_or_id & 0xFFFF) as u16
    }

    /// Check if this points to a subdirectory (vs data entry).
    #[must_use]
    pub fn is_directory(self) -> bool {
        (self.offset_to_data & 0x8000_0000) != 0
    }

    /// Get the offset to the subdirectory or data entry, relative to the start
    /// of the resource directory.
    #[must_use]
    pub fn data_offset(self) -> u32 {
        self.offset_to_data & 0x7FFF_FFFF
    }
}

/// `IMAGE_RESOURCE_DATA_ENTRY` (16 bytes): leaf of the resource tree
/// describing one resource payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceDataEntry {
    /// RVA of the resource data.
    pub offset_to_data: u32,
    /// Size of the resource data.
    pub size: u32,
    /// Code page.
    pub code_page: u32,
    /// Reserved.
    pub reserved: u32,
}

impl ResourceDataEntry {
    /// Size of `IMAGE_RESOURCE_DATA_ENTRY` in bytes.
    pub const SIZE: usize = 16;

    /// Parse an `IMAGE_RESOURCE_DATA_ENTRY` from little-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns a buffer-too-small error if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }

        Ok(Self {
            offset_to_data: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            size: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            code_page: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            reserved: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        })
    }

    /// Serialize to the little-endian on-disk layout.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.offset_to_data.to_le_bytes());
        buf[4..8].copy_from_slice(&self.size.to_le_bytes());
        buf[8..12].copy_from_slice(&self.code_page.to_le_bytes());
        buf[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        buf
    }
}

/// A parsed resource entry with optional data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    /// Resource type (level 1).
    pub type_id: ResourceId,
    /// Resource name/ID (level 2).
    pub name: ResourceId,
    /// Language ID (level 3).
    pub language: u16,
    /// RVA of the resource data.
    pub data_rva: u32,
    /// Size of the resource data.
    pub size: u32,
    /// Code page.
    pub code_page: u32,
    /// The actual resource data (only populated if parsed with `parse_with_data`).
    pub data: Option<Vec<u8>>,
}

impl Resource {
    /// Check if this is a specific resource type.
    #[must_use]
    pub fn is_type(&self, rt: ResourceType) -> bool {
        matches!(&self.type_id, ResourceId::Id(id) if *id == rt as u16)
    }

    /// Get as standard resource type.
    #[must_use]
    pub fn get_type(&self) -> Option<ResourceType> {
        self.type_id.as_resource_type()
    }

    /// Check if the resource data is loaded.
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.data.is_some()
    }
}

/// Parsed resource directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceDirectory {
    /// All resources in the directory.
    pub resources: Vec<Resource>,
}

fn checked_resource_rva(
    base_rva: u32,
    directory_size: u32,
    relative_offset: u32,
    length: usize,
    context: &str,
) -> Result<u32> {
    let length = u64::try_from(length)
        .map_err(|_| Error::invalid_data_directory(format!("{context} length overflow")))?;
    let relative_end = u64::from(relative_offset)
        .checked_add(length)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} range overflow")))?;
    if relative_end > u64::from(directory_size) {
        return Err(Error::invalid_data_directory(format!(
            "{context} range {relative_offset:#x}..{relative_end:#x} exceeds resource directory size {directory_size:#x}"
        )));
    }
    base_rva
        .checked_add(relative_offset)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} RVA overflow")))
}

mod build;
mod parse;

pub use build::{ResourceBuilder, ResourceEntry};

#[cfg(test)]
mod tests;
