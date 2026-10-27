//! Load Configuration Directory parsing and building.
//!
//! The Load Configuration Directory contains security features like
//! SafeSEH, CFG (Control Flow Guard), and other runtime configuration.

use crate::prelude::*;
use crate::{Error, Result};

/// The structure's Size bounds the available versioned prefix. Zero Size
/// retains the legacy directory-size convention, not an absent directory.
fn directory_prefix(data: &[u8]) -> Result<(u32, &[u8])> {
    const HEADER_SIZE: usize = core::mem::size_of::<u32>();
    if data.len() < HEADER_SIZE {
        return Err(Error::buffer_too_small(HEADER_SIZE, data.len()));
    }
    let size = u32::from_le_bytes(
        data[..HEADER_SIZE]
            .try_into()
            .expect("the Size field is present"),
    );
    let declared_size = if size == 0 { data.len() } else { size as usize };
    if declared_size < HEADER_SIZE || declared_size > data.len() {
        return Err(Error::invalid_data_directory(format!(
            "load-config size {declared_size} is outside the available {} bytes",
            data.len()
        )));
    }
    Ok((size, &data[..declared_size]))
}

/// A version may omit a whole field, but never supply only part of its value.
fn directory_field<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N]> {
    if offset >= data.len() {
        return Ok([0; N]);
    }
    let bytes = data.get(offset..offset + N).ok_or_else(|| {
        Error::invalid_data_directory(format!("load-config field at {offset:#x} is truncated"))
    })?;
    Ok(bytes
        .try_into()
        .expect("the complete field has its declared width"))
}

/// `IMAGE_LOAD_CONFIG_DIRECTORY32` (Windows 10+) - 192 bytes
/// Note: Size varies by Windows version; we parse what's available.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadConfigDirectory32 {
    /// Size of this structure.
    pub size: u32,
    /// Time/date stamp.
    pub time_date_stamp: u32,
    /// Major version.
    pub major_version: u16,
    /// Minor version.
    pub minor_version: u16,
    /// Global flags to clear.
    pub global_flags_clear: u32,
    /// Global flags to set.
    pub global_flags_set: u32,
    /// Default timeout for critical sections.
    pub critical_section_default_timeout: u32,
    /// Size of minimum memory to de-commit.
    pub de_commit_free_block_threshold: u32,
    /// Size of minimum total memory to de-commit.
    pub de_commit_total_free_threshold: u32,
    /// VA of lock prefix table (x86 only).
    pub lock_prefix_table: u32,
    /// Maximum allocation size.
    pub maximum_allocation_size: u32,
    /// Maximum virtual memory size.
    pub virtual_memory_threshold: u32,
    /// Process affinity mask.
    pub process_affinity_mask: u32,
    /// Process heap flags.
    pub process_heap_flags: u32,
    /// Service pack version.
    pub csd_version: u16,
    /// Dependent load flags.
    pub dependent_load_flags: u16,
    /// VA of edit list (reserved).
    pub edit_list: u32,
    /// VA of security cookie.
    pub security_cookie: u32,
    /// VA of SEH handler table.
    pub se_handler_table: u32,
    /// Number of SEH handlers.
    pub se_handler_count: u32,
    /// VA of CFG check function pointer.
    pub guard_cf_check_function_pointer: u32,
    /// VA of CFG dispatch function pointer.
    pub guard_cf_dispatch_function_pointer: u32,
    /// VA of CFG function table.
    pub guard_cf_function_table: u32,
    /// Number of entries in CFG function table.
    pub guard_cf_function_count: u32,
    /// CFG flags.
    pub guard_flags: u32,
    /// Bytes in the versioned structure beyond the fields understood here.
    pub trailing_data: Vec<u8>,
}

impl LoadConfigDirectory32 {
    /// Default emitted size before optional SafeSEH and CFG fields.
    pub const MIN_SIZE: usize = 64;
    /// Size through `GuardFlags`; later versioned fields are preserved opaquely.
    pub const SIZE_WITH_CFG: usize = 92;

    /// Parses a whole-field versioned prefix, including legacy short records.
    ///
    /// # Errors
    ///
    /// Returns a `BufferTooSmall` error if `data` cannot hold the `Size` field,
    /// or an `InvalidDataDirectory` error if the declared size exceeds `data`
    /// or truncates a field.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (size, data) = directory_prefix(data)?;
        let word = |offset| directory_field(data, offset).map(u32::from_le_bytes);
        let half = |offset| directory_field(data, offset).map(u16::from_le_bytes);
        Ok(Self {
            size,
            time_date_stamp: word(4)?,
            major_version: half(8)?,
            minor_version: half(10)?,
            global_flags_clear: word(12)?,
            global_flags_set: word(16)?,
            critical_section_default_timeout: word(20)?,
            de_commit_free_block_threshold: word(24)?,
            de_commit_total_free_threshold: word(28)?,
            lock_prefix_table: word(32)?,
            maximum_allocation_size: word(36)?,
            virtual_memory_threshold: word(40)?,
            process_heap_flags: word(44)?,
            process_affinity_mask: word(48)?,
            csd_version: half(52)?,
            dependent_load_flags: half(54)?,
            edit_list: word(56)?,
            security_cookie: word(60)?,
            se_handler_table: word(64)?,
            se_handler_count: word(68)?,
            guard_cf_check_function_pointer: word(72)?,
            guard_cf_dispatch_function_pointer: word(76)?,
            guard_cf_function_table: word(80)?,
            guard_cf_function_count: word(84)?,
            guard_flags: word(88)?,
            trailing_data: data.get(Self::SIZE_WITH_CFG..).unwrap_or_default().to_vec(),
        })
    }

    /// Serialize to bytes (up to the size field value).
    ///
    /// # Panics
    ///
    /// Panics if the serialized size exceeds `u32`; use [`Self::try_to_bytes`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("load-config build failed: use try_to_bytes()")
    }

    /// Serialize with checked versioned/trailing size arithmetic.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the serialized size exceeds `u32`.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        let known_size = if self.guard_flags != 0 {
            Self::SIZE_WITH_CFG
        } else if self.guard_cf_function_count != 0 {
            88
        } else if self.guard_cf_function_table != 0 {
            84
        } else if self.guard_cf_dispatch_function_pointer != 0 {
            80
        } else if self.guard_cf_check_function_pointer != 0 {
            76
        } else if self.se_handler_table != 0 || self.se_handler_count != 0 {
            72
        } else {
            Self::MIN_SIZE
        };
        let trailing_size = if self.trailing_data.is_empty() {
            0
        } else {
            Self::SIZE_WITH_CFG
                .checked_add(self.trailing_data.len())
                .ok_or_else(|| Error::invalid_data_directory("load-config size overflow"))?
        };
        let output_size = (self.size as usize).max(known_size).max(trailing_size);
        let encoded_size = u32::try_from(output_size)
            .map_err(|_| Error::invalid_data_directory("load-config size exceeds u32"))?;
        let mut buf = vec![0u8; output_size];

        buf[0..4].copy_from_slice(&encoded_size.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..10].copy_from_slice(&self.major_version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.minor_version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.global_flags_clear.to_le_bytes());
        buf[16..20].copy_from_slice(&self.global_flags_set.to_le_bytes());
        buf[20..24].copy_from_slice(&self.critical_section_default_timeout.to_le_bytes());
        buf[24..28].copy_from_slice(&self.de_commit_free_block_threshold.to_le_bytes());
        buf[28..32].copy_from_slice(&self.de_commit_total_free_threshold.to_le_bytes());
        buf[32..36].copy_from_slice(&self.lock_prefix_table.to_le_bytes());
        buf[36..40].copy_from_slice(&self.maximum_allocation_size.to_le_bytes());
        buf[40..44].copy_from_slice(&self.virtual_memory_threshold.to_le_bytes());
        buf[44..48].copy_from_slice(&self.process_heap_flags.to_le_bytes());
        buf[48..52].copy_from_slice(&self.process_affinity_mask.to_le_bytes());
        buf[52..54].copy_from_slice(&self.csd_version.to_le_bytes());
        buf[54..56].copy_from_slice(&self.dependent_load_flags.to_le_bytes());
        buf[56..60].copy_from_slice(&self.edit_list.to_le_bytes());
        buf[60..64].copy_from_slice(&self.security_cookie.to_le_bytes());

        if output_size >= 72 {
            buf[64..68].copy_from_slice(&self.se_handler_table.to_le_bytes());
            buf[68..72].copy_from_slice(&self.se_handler_count.to_le_bytes());
        }

        if output_size >= 76 {
            buf[72..76].copy_from_slice(&self.guard_cf_check_function_pointer.to_le_bytes());
        }
        if output_size >= 80 {
            buf[76..80].copy_from_slice(&self.guard_cf_dispatch_function_pointer.to_le_bytes());
        }
        if output_size >= 84 {
            buf[80..84].copy_from_slice(&self.guard_cf_function_table.to_le_bytes());
        }
        if output_size >= 88 {
            buf[84..88].copy_from_slice(&self.guard_cf_function_count.to_le_bytes());
        }
        if output_size >= Self::SIZE_WITH_CFG {
            buf[88..92].copy_from_slice(&self.guard_flags.to_le_bytes());
        }

        if output_size > Self::SIZE_WITH_CFG && !self.trailing_data.is_empty() {
            let count = self
                .trailing_data
                .len()
                .min(output_size - Self::SIZE_WITH_CFG);
            buf[Self::SIZE_WITH_CFG..Self::SIZE_WITH_CFG + count]
                .copy_from_slice(&self.trailing_data[..count]);
        }

        Ok(buf)
    }

    /// Check if CFG is enabled.
    #[must_use]
    pub fn has_cfg(&self) -> bool {
        self.guard_cf_function_table != 0 || self.guard_flags != 0
    }

    /// Check if `SafeSEH` is present.
    #[must_use]
    pub fn has_safe_seh(&self) -> bool {
        self.se_handler_table != 0
    }
}

/// `IMAGE_LOAD_CONFIG_DIRECTORY64` (Windows 10+)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadConfigDirectory64 {
    /// Size of this structure.
    pub size: u32,
    /// Time/date stamp.
    pub time_date_stamp: u32,
    /// Major version.
    pub major_version: u16,
    /// Minor version.
    pub minor_version: u16,
    /// Global flags to clear.
    pub global_flags_clear: u32,
    /// Global flags to set.
    pub global_flags_set: u32,
    /// Default timeout for critical sections.
    pub critical_section_default_timeout: u32,
    /// Size of minimum memory to de-commit.
    pub de_commit_free_block_threshold: u64,
    /// Size of minimum total memory to de-commit.
    pub de_commit_total_free_threshold: u64,
    /// VA of lock prefix table (x86 only).
    pub lock_prefix_table: u64,
    /// Maximum allocation size.
    pub maximum_allocation_size: u64,
    /// Maximum virtual memory size.
    pub virtual_memory_threshold: u64,
    /// Process affinity mask.
    pub process_affinity_mask: u64,
    /// Process heap flags.
    pub process_heap_flags: u32,
    /// Service pack version.
    pub csd_version: u16,
    /// Dependent load flags.
    pub dependent_load_flags: u16,
    /// VA of edit list (reserved).
    pub edit_list: u64,
    /// VA of security cookie.
    pub security_cookie: u64,
    /// VA of SEH handler table (unused on x64).
    pub se_handler_table: u64,
    /// Number of SEH handlers (unused on x64).
    pub se_handler_count: u64,
    /// VA of CFG check function pointer.
    pub guard_cf_check_function_pointer: u64,
    /// VA of CFG dispatch function pointer.
    pub guard_cf_dispatch_function_pointer: u64,
    /// VA of CFG function table.
    pub guard_cf_function_table: u64,
    /// Number of entries in CFG function table.
    pub guard_cf_function_count: u64,
    /// CFG flags.
    pub guard_flags: u32,
    /// Bytes in the versioned structure beyond the fields understood here.
    pub trailing_data: Vec<u8>,
}

impl LoadConfigDirectory64 {
    /// Default emitted size before optional CFG fields.
    pub const MIN_SIZE: usize = 112;
    /// Size through `GuardFlags`; later versioned fields are preserved opaquely.
    pub const SIZE_WITH_CFG: usize = 148;

    /// Parses a whole-field versioned prefix, including legacy short records.
    ///
    /// # Errors
    ///
    /// Returns a `BufferTooSmall` error if `data` cannot hold the `Size` field,
    /// or an `InvalidDataDirectory` error if the declared size exceeds `data`
    /// or truncates a field.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (size, data) = directory_prefix(data)?;
        let wide = |offset| directory_field(data, offset).map(u64::from_le_bytes);
        let word = |offset| directory_field(data, offset).map(u32::from_le_bytes);
        let half = |offset| directory_field(data, offset).map(u16::from_le_bytes);
        Ok(Self {
            size,
            time_date_stamp: word(4)?,
            major_version: half(8)?,
            minor_version: half(10)?,
            global_flags_clear: word(12)?,
            global_flags_set: word(16)?,
            critical_section_default_timeout: word(20)?,
            de_commit_free_block_threshold: wide(24)?,
            de_commit_total_free_threshold: wide(32)?,
            lock_prefix_table: wide(40)?,
            maximum_allocation_size: wide(48)?,
            virtual_memory_threshold: wide(56)?,
            process_affinity_mask: wide(64)?,
            process_heap_flags: word(72)?,
            csd_version: half(76)?,
            dependent_load_flags: half(78)?,
            edit_list: wide(80)?,
            security_cookie: wide(88)?,
            se_handler_table: wide(96)?,
            se_handler_count: wide(104)?,
            guard_cf_check_function_pointer: wide(112)?,
            guard_cf_dispatch_function_pointer: wide(120)?,
            guard_cf_function_table: wide(128)?,
            guard_cf_function_count: wide(136)?,
            guard_flags: word(144)?,
            trailing_data: data.get(Self::SIZE_WITH_CFG..).unwrap_or_default().to_vec(),
        })
    }

    /// Serialize to bytes (up to the size field value).
    ///
    /// # Panics
    ///
    /// Panics if the serialized size exceeds `u32`; use [`Self::try_to_bytes`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("load-config build failed: use try_to_bytes()")
    }

    /// Serialize with checked versioned/trailing size arithmetic.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the serialized size exceeds `u32`.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        let known_size = if self.guard_flags != 0 {
            Self::SIZE_WITH_CFG
        } else if self.guard_cf_function_count != 0 {
            144
        } else if self.guard_cf_function_table != 0 {
            136
        } else if self.guard_cf_dispatch_function_pointer != 0 {
            128
        } else if self.guard_cf_check_function_pointer != 0 {
            120
        } else {
            Self::MIN_SIZE
        };
        let trailing_size = if self.trailing_data.is_empty() {
            0
        } else {
            Self::SIZE_WITH_CFG
                .checked_add(self.trailing_data.len())
                .ok_or_else(|| Error::invalid_data_directory("load-config size overflow"))?
        };
        let output_size = (self.size as usize).max(known_size).max(trailing_size);
        let encoded_size = u32::try_from(output_size)
            .map_err(|_| Error::invalid_data_directory("load-config size exceeds u32"))?;
        let mut buf = vec![0u8; output_size];

        buf[0..4].copy_from_slice(&encoded_size.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..10].copy_from_slice(&self.major_version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.minor_version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.global_flags_clear.to_le_bytes());
        buf[16..20].copy_from_slice(&self.global_flags_set.to_le_bytes());
        buf[20..24].copy_from_slice(&self.critical_section_default_timeout.to_le_bytes());
        buf[24..32].copy_from_slice(&self.de_commit_free_block_threshold.to_le_bytes());
        buf[32..40].copy_from_slice(&self.de_commit_total_free_threshold.to_le_bytes());
        buf[40..48].copy_from_slice(&self.lock_prefix_table.to_le_bytes());
        buf[48..56].copy_from_slice(&self.maximum_allocation_size.to_le_bytes());
        buf[56..64].copy_from_slice(&self.virtual_memory_threshold.to_le_bytes());
        buf[64..72].copy_from_slice(&self.process_affinity_mask.to_le_bytes());
        buf[72..76].copy_from_slice(&self.process_heap_flags.to_le_bytes());
        buf[76..78].copy_from_slice(&self.csd_version.to_le_bytes());
        buf[78..80].copy_from_slice(&self.dependent_load_flags.to_le_bytes());
        buf[80..88].copy_from_slice(&self.edit_list.to_le_bytes());
        buf[88..96].copy_from_slice(&self.security_cookie.to_le_bytes());
        buf[96..104].copy_from_slice(&self.se_handler_table.to_le_bytes());
        buf[104..112].copy_from_slice(&self.se_handler_count.to_le_bytes());

        if output_size >= 120 {
            buf[112..120].copy_from_slice(&self.guard_cf_check_function_pointer.to_le_bytes());
        }
        if output_size >= 128 {
            buf[120..128].copy_from_slice(&self.guard_cf_dispatch_function_pointer.to_le_bytes());
        }
        if output_size >= 136 {
            buf[128..136].copy_from_slice(&self.guard_cf_function_table.to_le_bytes());
        }
        if output_size >= 144 {
            buf[136..144].copy_from_slice(&self.guard_cf_function_count.to_le_bytes());
        }
        if output_size >= Self::SIZE_WITH_CFG {
            buf[144..148].copy_from_slice(&self.guard_flags.to_le_bytes());
        }

        if output_size > Self::SIZE_WITH_CFG && !self.trailing_data.is_empty() {
            let count = self
                .trailing_data
                .len()
                .min(output_size - Self::SIZE_WITH_CFG);
            buf[Self::SIZE_WITH_CFG..Self::SIZE_WITH_CFG + count]
                .copy_from_slice(&self.trailing_data[..count]);
        }

        Ok(buf)
    }

    /// Check if CFG is enabled.
    #[must_use]
    pub fn has_cfg(&self) -> bool {
        self.guard_cf_function_table != 0 || self.guard_flags != 0
    }
}

/// Load Config Directory (either 32 or 64-bit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadConfigDirectory {
    /// PE32 `IMAGE_LOAD_CONFIG_DIRECTORY32`.
    Config32(LoadConfigDirectory32),
    /// PE32+ `IMAGE_LOAD_CONFIG_DIRECTORY64`.
    Config64(LoadConfigDirectory64),
}

impl LoadConfigDirectory {
    /// Parses the 32- or 64-bit layout selected by `is_64bit`.
    ///
    /// # Errors
    ///
    /// Returns a `BufferTooSmall` error if `data` cannot hold the `Size` field,
    /// or an `InvalidDataDirectory` error if the declared size exceeds `data`
    /// or truncates a field.
    pub fn parse(data: &[u8], is_64bit: bool) -> Result<Self> {
        if is_64bit {
            Ok(Self::Config64(LoadConfigDirectory64::parse(data)?))
        } else {
            Ok(Self::Config32(LoadConfigDirectory32::parse(data)?))
        }
    }

    /// Serialize to bytes (up to the size field value).
    ///
    /// # Panics
    ///
    /// Panics if the serialized size exceeds `u32`; use [`Self::try_to_bytes`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("load-config build failed: use try_to_bytes()")
    }

    /// Serialize with checked versioned/trailing size arithmetic.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the serialized size exceeds `u32`.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Config32(c) => c.try_to_bytes(),
            Self::Config64(c) => c.try_to_bytes(),
        }
    }

    /// VA of the security cookie, widened to `u64`.
    #[must_use]
    pub fn security_cookie_va(&self) -> u64 {
        match self {
            Self::Config32(c) => u64::from(c.security_cookie),
            Self::Config64(c) => c.security_cookie,
        }
    }

    /// Check if CFG is enabled.
    #[must_use]
    pub fn has_cfg(&self) -> bool {
        match self {
            Self::Config32(c) => c.has_cfg(),
            Self::Config64(c) => c.has_cfg(),
        }
    }
}

/// `GuardFlags` values (`IMAGE_GUARD_*`) for the load-config directory.
pub mod guard_flags {
    /// `IMAGE_GUARD_CF_INSTRUMENTED`: module performs CFG checks.
    pub const CF_INSTRUMENTED: u32 = 0x0000_0100;
    /// `IMAGE_GUARD_CFW_INSTRUMENTED`: module performs CFG and write-integrity checks.
    pub const CFW_INSTRUMENTED: u32 = 0x0000_0200;
    /// `IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT`: module contains valid CFG target metadata.
    pub const CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
    /// `IMAGE_GUARD_SECURITY_COOKIE_UNUSED`: module does not use the `/GS` security cookie.
    pub const SECURITY_COOKIE_UNUSED: u32 = 0x0000_0800;
    /// `IMAGE_GUARD_PROTECT_DELAYLOAD_IAT`: module supports read-only delay-load IAT.
    pub const PROTECT_DELAYLOAD_IAT: u32 = 0x0000_1000;
    /// `IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION`: delay-load IAT is in its own section.
    pub const DELAYLOAD_IAT_IN_ITS_OWN_SECTION: u32 = 0x0000_2000;
    /// `IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT`: module contains suppressed-export information.
    pub const CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x0000_4000;
    /// `IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION`: module enables suppression of exports.
    pub const CF_ENABLE_EXPORT_SUPPRESSION: u32 = 0x0000_8000;
    /// `IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT`: module contains longjmp target information.
    pub const CF_LONGJUMP_TABLE_PRESENT: u32 = 0x0001_0000;
    /// `IMAGE_GUARD_RF_INSTRUMENTED`: module contains return-flow instrumentation.
    pub const RF_INSTRUMENTED: u32 = 0x0002_0000;
    /// `IMAGE_GUARD_RF_ENABLE`: module requests return-flow protection.
    pub const RF_ENABLE: u32 = 0x0004_0000;
    /// `IMAGE_GUARD_RF_STRICT`: module requests return-flow protection in strict mode.
    pub const RF_STRICT: u32 = 0x0008_0000;
    /// `IMAGE_GUARD_RETPOLINE_PRESENT`: module was built with retpoline support.
    pub const RETPOLINE_PRESENT: u32 = 0x0010_0000;
}

/// Control Flow Guard settings for [`LoadConfigBuilder::build_with_cfg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CfgSettings {
    /// VA of the `/GS` security cookie.
    pub security_cookie_va: u64,
    /// VA of the CFG check function pointer (`GuardCFCheckFunctionPointer`).
    pub guard_cf_check_va: u64,
    /// VA of the CFG dispatch function pointer (`GuardCFDispatchFunctionPointer`).
    pub guard_cf_dispatch_va: u64,
    /// VA of the CFG function table (`GuardCFFunctionTable`).
    pub guard_cf_table_va: u64,
    /// Number of entries in the CFG function table (`GuardCFFunctionCount`).
    pub guard_cf_count: u64,
    /// `GuardFlags` value; see [`guard_flags`].
    pub flags: u32,
}

/// Builder for Load Configuration directories.
///
/// `LoadConfig` directories contain security features like `SafeSEH` and CFG.
/// This builder simplifies creating and modifying these complex structures.
///
/// # Example
///
/// ```
/// use portex::loadconfig::{LoadConfigBuilder, guard_flags};
///
/// // Create a LoadConfig builder for 64-bit PE
/// let builder = LoadConfigBuilder::new(true);
///
/// // Build with security cookie
/// let (data, size) = builder.build_with_cookie(0x140001000);
/// assert!(size > 0);
/// ```
#[derive(Debug, Clone)]
pub struct LoadConfigBuilder {
    /// Whether this is a 64-bit PE.
    is_64bit: bool,
}

impl LoadConfigBuilder {
    /// Create a new `LoadConfig` builder.
    #[must_use]
    pub fn new(is_64bit: bool) -> Self {
        Self { is_64bit }
    }

    /// Build a basic `LoadConfig` with just a security cookie.
    ///
    /// # Arguments
    /// * `security_cookie_va` - Virtual address of the security cookie
    ///
    /// Returns (data, size)
    ///
    /// # Panics
    ///
    /// Panics if a PE32 builder is given a cookie VA that exceeds `u32`; use
    /// [`Self::try_build_with_cookie`] for fallible building.
    #[must_use]
    pub fn build_with_cookie(&self, security_cookie_va: u64) -> (Vec<u8>, u32) {
        self.try_build_with_cookie(security_cookie_va)
            .expect("load-config build failed: use try_build_with_cookie()")
    }

    /// Build a basic load-config directory without truncating PE32 values.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if this is a PE32 builder and
    /// `security_cookie_va` does not fit in `u32`.
    pub fn try_build_with_cookie(&self, security_cookie_va: u64) -> Result<(Vec<u8>, u32)> {
        if self.is_64bit {
            let config = LoadConfigDirectory64 {
                size: Self::size_field(LoadConfigDirectory64::MIN_SIZE)?,
                security_cookie: security_cookie_va,
                ..Default::default()
            };
            Self::serialize(&LoadConfigDirectory::Config64(config))
        } else {
            let config = LoadConfigDirectory32 {
                size: Self::size_field(LoadConfigDirectory32::MIN_SIZE)?,
                security_cookie: Self::pe32_value(security_cookie_va, "security cookie")?,
                ..Default::default()
            };
            Self::serialize(&LoadConfigDirectory::Config32(config))
        }
    }

    /// Build from an existing `LoadConfigDirectory`.
    ///
    /// Returns (data, size)
    ///
    /// # Panics
    ///
    /// Panics if the directory bitness does not match the builder or its size
    /// exceeds `u32`; use [`Self::try_build`] for fallible building.
    #[must_use]
    pub fn build(&self, config: &LoadConfigDirectory) -> (Vec<u8>, u32) {
        self.try_build(config)
            .expect("load-config build failed: use try_build()")
    }

    /// Build from an existing directory, checking the configured PE width.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the directory bitness does not
    /// match the builder or the serialized size exceeds `u32`.
    pub fn try_build(&self, config: &LoadConfigDirectory) -> Result<(Vec<u8>, u32)> {
        let matches_width = matches!(
            (self.is_64bit, config),
            (true, LoadConfigDirectory::Config64(_)) | (false, LoadConfigDirectory::Config32(_))
        );
        if !matches_width {
            return Err(Error::invalid_data_directory(
                "load-config bitness does not match the target image",
            ));
        }
        Self::serialize(config)
    }

    /// Build a `LoadConfig` with CFG (Control Flow Guard) settings.
    ///
    /// Returns (data, size)
    ///
    /// # Panics
    ///
    /// Panics if a PE32 builder is given a value in `cfg` that exceeds `u32`;
    /// use [`Self::try_build_with_cfg`] for fallible building.
    #[must_use]
    pub fn build_with_cfg(&self, cfg: &CfgSettings) -> (Vec<u8>, u32) {
        self.try_build_with_cfg(cfg)
            .expect("load-config build failed: use try_build_with_cfg()")
    }

    /// Build a CFG-enabled load-config directory with checked PE32 values.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if this is a PE32 builder and a
    /// VA or the function count in `cfg` does not fit in `u32`.
    pub fn try_build_with_cfg(&self, cfg: &CfgSettings) -> Result<(Vec<u8>, u32)> {
        if self.is_64bit {
            let config = LoadConfigDirectory64 {
                size: Self::size_field(LoadConfigDirectory64::SIZE_WITH_CFG)?,
                security_cookie: cfg.security_cookie_va,
                guard_cf_check_function_pointer: cfg.guard_cf_check_va,
                guard_cf_dispatch_function_pointer: cfg.guard_cf_dispatch_va,
                guard_cf_function_table: cfg.guard_cf_table_va,
                guard_cf_function_count: cfg.guard_cf_count,
                guard_flags: cfg.flags,
                ..Default::default()
            };
            Self::serialize(&LoadConfigDirectory::Config64(config))
        } else {
            let config = LoadConfigDirectory32 {
                size: Self::size_field(LoadConfigDirectory32::SIZE_WITH_CFG)?,
                security_cookie: Self::pe32_value(cfg.security_cookie_va, "security cookie")?,
                guard_cf_check_function_pointer: Self::pe32_value(
                    cfg.guard_cf_check_va,
                    "CFG check function",
                )?,
                guard_cf_dispatch_function_pointer: Self::pe32_value(
                    cfg.guard_cf_dispatch_va,
                    "CFG dispatch function",
                )?,
                guard_cf_function_table: Self::pe32_value(
                    cfg.guard_cf_table_va,
                    "CFG function table",
                )?,
                guard_cf_function_count: Self::pe32_value(
                    cfg.guard_cf_count,
                    "CFG function count",
                )?,
                guard_flags: cfg.flags,
                ..Default::default()
            };
            Self::serialize(&LoadConfigDirectory::Config32(config))
        }
    }

    fn size_field(size: usize) -> Result<u32> {
        u32::try_from(size)
            .map_err(|_| Error::invalid_data_directory("load-config size exceeds u32"))
    }

    fn serialize(config: &LoadConfigDirectory) -> Result<(Vec<u8>, u32)> {
        let data = config.try_to_bytes()?;
        let size = u32::try_from(data.len())
            .map_err(|_| Error::invalid_data_directory("load-config size exceeds u32"))?;
        Ok((data, size))
    }

    fn pe32_value(value: u64, field: &str) -> Result<u32> {
        u32::try_from(value).map_err(|_| {
            Error::invalid_data_directory(format!("{field} does not fit a PE32 load config"))
        })
    }

    /// Calculate the size needed for `LoadConfig` data.
    #[must_use]
    pub fn size(&self, with_cfg: bool) -> usize {
        if self.is_64bit {
            if with_cfg {
                LoadConfigDirectory64::SIZE_WITH_CFG
            } else {
                LoadConfigDirectory64::MIN_SIZE
            }
        } else if with_cfg {
            LoadConfigDirectory32::SIZE_WITH_CFG
        } else {
            LoadConfigDirectory32::MIN_SIZE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_config_32_min_size() {
        assert_eq!(LoadConfigDirectory32::MIN_SIZE, 64);
    }

    #[test]
    fn test_load_config_64_min_size() {
        assert_eq!(LoadConfigDirectory64::MIN_SIZE, 112);
    }

    #[test]
    fn test_load_config_32_roundtrip() {
        let original = LoadConfigDirectory32 {
            size: 104,
            time_date_stamp: 0x1234_5678,
            major_version: 1,
            minor_version: 0,
            security_cookie: 0x0040_1000,
            se_handler_table: 0x0040_2000,
            se_handler_count: 5,
            guard_cf_function_table: 0x0040_3000,
            guard_cf_function_count: 10,
            guard_flags: guard_flags::CF_INSTRUMENTED,
            ..Default::default()
        };

        let bytes = original.to_bytes();
        let parsed = LoadConfigDirectory32::parse(&bytes).unwrap();
        assert_eq!(original.size, parsed.size);
        assert_eq!(original.security_cookie, parsed.security_cookie);
        assert_eq!(original.guard_flags, parsed.guard_flags);
    }

    #[test]
    fn test_load_config_64_roundtrip() {
        let original = LoadConfigDirectory64 {
            size: 148,
            security_cookie: 0x0000_0001_4000_1000,
            guard_cf_function_table: 0x0000_0001_4000_2000,
            guard_cf_function_count: 20,
            guard_flags: guard_flags::CF_INSTRUMENTED | guard_flags::CF_FUNCTION_TABLE_PRESENT,
            ..Default::default()
        };

        let bytes = original.to_bytes();
        let parsed = LoadConfigDirectory64::parse(&bytes).unwrap();
        assert_eq!(original.size, parsed.size);
        assert_eq!(original.security_cookie, parsed.security_cookie);
        assert_eq!(original.guard_flags, parsed.guard_flags);
    }

    #[test]
    fn legacy_prefixes_preserve_present_fields_and_omit_only_whole_fields() {
        let mut early32 = vec![0; 60];
        early32[..4].copy_from_slice(&60_u32.to_le_bytes());
        early32[32..36].copy_from_slice(&0x0040_1000_u32.to_le_bytes());
        let parsed32 = LoadConfigDirectory32::parse(&early32).expect("a whole pre-cookie prefix");
        assert_eq!(parsed32.lock_prefix_table, 0x0040_1000);
        assert_eq!(parsed32.security_cookie, 0);
        assert_eq!(parsed32.se_handler_table, 0);
        let mut cookie64 = vec![0; 96];
        cookie64[..4].copy_from_slice(&96_u32.to_le_bytes());
        cookie64[88..96].copy_from_slice(&0x1_4000_1000_u64.to_le_bytes());
        let parsed64 = LoadConfigDirectory64::parse(&cookie64)
            .expect("the cookie predates reserved SEH fields");
        assert_eq!(parsed64.security_cookie, 0x1_4000_1000);
        assert_eq!(parsed64.se_handler_table, 0);
        assert_eq!(parsed64.guard_flags, 0);
        cookie64[..4].fill(0);
        assert_eq!(
            LoadConfigDirectory64::parse(&cookie64)
                .expect("legacy Size zero uses available bytes")
                .security_cookie,
            parsed64.security_cookie
        );
        let mut bounded = vec![0xff; 148];
        bounded[..4].copy_from_slice(&4_u32.to_le_bytes());
        let absent = LoadConfigDirectory64::parse(&bounded)
            .expect("bytes beyond declared Size are not fields");
        assert_eq!(absent.security_cookie, 0);
        assert_eq!(absent.trailing_data, Vec::<u8>::new());
    }

    #[test]
    fn versioned_prefixes_reject_partial_fields_and_unreadable_declared_sizes() {
        for size in [5_usize, 9, 53, 61, 65, 73, 89] {
            let mut bytes = vec![0; size];
            bytes[..4].copy_from_slice(
                &u32::try_from(size)
                    .expect("test size fits u32")
                    .to_le_bytes(),
            );
            assert!(
                LoadConfigDirectory32::parse(&bytes).is_err(),
                "partial PE32 field at Size {size}"
            );
        }
        for size in [5_usize, 9, 25, 41, 77, 89, 97, 105, 113, 145] {
            let mut bytes = vec![0; size];
            bytes[..4].copy_from_slice(
                &u32::try_from(size)
                    .expect("test size fits u32")
                    .to_le_bytes(),
            );
            assert!(
                LoadConfigDirectory64::parse(&bytes).is_err(),
                "partial PE32+ field at Size {size}"
            );
        }
        for declared in [1_u32, 3, 97] {
            let mut bytes = vec![0; 96];
            bytes[..4].copy_from_slice(&declared.to_le_bytes());
            assert!(LoadConfigDirectory64::parse(&bytes).is_err());
        }
        assert!(LoadConfigDirectory32::parse(&[]).is_err());
        assert!(LoadConfigDirectory64::parse(&[0; 3]).is_err());
    }
}
