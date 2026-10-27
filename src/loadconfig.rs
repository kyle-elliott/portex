//! Parse and build the load configuration directory.
//!
//! The load configuration directory contains security features, for example SafeSEH and CFG
//! (Control Flow Guard). It also contains other runtime configuration.

use crate::prelude::*;
use crate::{Error, Result};

/// Return the `Size` field and the versioned prefix of the structure.
///
/// The `Size` field limits the available versioned prefix. A `Size` of zero does not mean that
/// the directory is absent. In this case, the legacy convention applies: use the directory size.
fn directory_prefix(data: &[u8]) -> Result<(u32, &[u8])> {
    const HEADER_SIZE: usize = core::mem::size_of::<u32>();
    let Some(size_bytes) = data.first_chunk::<HEADER_SIZE>() else {
        return Err(Error::buffer_too_small(HEADER_SIZE, data.len()));
    };
    let size = u32::from_le_bytes(*size_bytes);
    // A Size that does not fit `usize` is also larger than `data`.
    let declared_size = if size == 0 {
        data.len()
    } else {
        usize::try_from(size).unwrap_or(usize::MAX)
    };
    match data.get(..declared_size) {
        Some(prefix) if declared_size >= HEADER_SIZE => Ok((size, prefix)),
        _ => Err(Error::invalid_data_directory(format!(
            "load-config size {declared_size} is outside the available {} bytes",
            data.len()
        ))),
    }
}

/// Read the field at `offset`. A version can omit a whole field, but it cannot supply only
/// part of the value.
fn directory_field<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N]> {
    match data.get(offset..) {
        None | Some([]) => Ok([0; N]),
        Some(rest) => rest.first_chunk::<N>().copied().ok_or_else(|| {
            Error::invalid_data_directory(format!("load-config field at {offset:#x} is truncated"))
        }),
    }
}

/// Write `bytes` at `offset` in `buf` if the complete field fits.
///
/// A shorter record omits the whole field. In this case, the function writes nothing.
fn write_field(buf: &mut [u8], offset: usize, bytes: &[u8]) {
    if let Some(field) = buf
        .get_mut(offset..)
        .and_then(|rest| rest.get_mut(..bytes.len()))
    {
        field.copy_from_slice(bytes);
    }
}

/// Make the zeroed output buffer for a serialized load configuration.
///
/// The buffer length is the largest of these values:
///
/// - `size`, the `Size` field that the caller set.
/// - `known_size`, the end of the last field that is not zero.
/// - The end of `trailing`, which starts at `trailing_start`.
///
/// The function copies `trailing` into the buffer. It returns the buffer and its length as `u32`.
fn output_buffer(
    size: u32,
    known_size: usize,
    trailing_start: usize,
    trailing: &[u8],
) -> Result<(Vec<u8>, u32)> {
    let trailing_end = if trailing.is_empty() {
        0
    } else {
        trailing_start
            .checked_add(trailing.len())
            .ok_or_else(|| Error::invalid_data_directory("load-config size overflow"))?
    };
    let declared_size = usize::try_from(size)
        .map_err(|_| Error::invalid_data_directory("load-config size exceeds usize"))?;
    let output_size = declared_size.max(known_size).max(trailing_end);
    let encoded_size = u32::try_from(output_size)
        .map_err(|_| Error::invalid_data_directory("load-config size exceeds u32"))?;
    let mut buf = Vec::new();
    buf.try_reserve_exact(output_size)
        .map_err(|_| Error::invalid_data_directory("load-config is too large to allocate"))?;
    buf.resize(output_size, 0);
    if let Some(tail) = buf.get_mut(trailing_start..) {
        for (dst, src) in tail.iter_mut().zip(trailing) {
            *dst = *src;
        }
    }
    Ok((buf, encoded_size))
}

/// `IMAGE_LOAD_CONFIG_DIRECTORY32` (Windows 10 and later): 192 bytes.
///
/// The size changes with the Windows version. The parser reads the fields that are present.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadConfigDirectory32 {
    /// Size of this structure, in bytes.
    pub size: u32,
    /// Time and date stamp.
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
    /// VA of the lock prefix table (x86 only).
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
    /// VA of the edit list (reserved).
    pub edit_list: u32,
    /// VA of the security cookie.
    pub security_cookie: u32,
    /// VA of the SEH handler table.
    pub se_handler_table: u32,
    /// Number of SEH handlers.
    pub se_handler_count: u32,
    /// VA of the CFG check function pointer.
    pub guard_cf_check_function_pointer: u32,
    /// VA of the CFG dispatch function pointer.
    pub guard_cf_dispatch_function_pointer: u32,
    /// VA of the CFG function table.
    pub guard_cf_function_table: u32,
    /// Number of entries in the CFG function table.
    pub guard_cf_function_count: u32,
    /// CFG flags.
    pub guard_flags: u32,
    /// Bytes of the versioned structure after the fields that this type knows.
    pub trailing_data: Vec<u8>,
}

impl LoadConfigDirectory32 {
    /// Default output size, without the optional SafeSEH and CFG fields.
    pub const MIN_SIZE: usize = 64;
    /// Size up to and including `GuardFlags`. Later versioned fields stay as opaque bytes.
    pub const SIZE_WITH_CFG: usize = 92;

    /// Parse a versioned prefix of whole fields. Legacy short records are also valid.
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

    /// Serialize to bytes, up to the value of the `Size` field.
    ///
    /// # Panics
    ///
    /// Panics if the serialized size exceeds `u32` or if the allocation fails. For fallible
    /// serialization, use [`Self::try_to_bytes`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("load-config build failed: use try_to_bytes()")
    }

    /// Serialize to bytes, with checked arithmetic for the versioned size and the trailing size.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the serialized size exceeds `u32` or if the
    /// allocation fails.
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
        let (mut buf, encoded_size) = output_buffer(
            self.size,
            known_size,
            Self::SIZE_WITH_CFG,
            &self.trailing_data,
        )?;
        // The buffer holds at least `MIN_SIZE` bytes. Write a later field only if the buffer
        // holds the complete field.
        let mut put = |offset, bytes: &[u8]| write_field(&mut buf, offset, bytes);
        put(0, &encoded_size.to_le_bytes());
        put(4, &self.time_date_stamp.to_le_bytes());
        put(8, &self.major_version.to_le_bytes());
        put(10, &self.minor_version.to_le_bytes());
        put(12, &self.global_flags_clear.to_le_bytes());
        put(16, &self.global_flags_set.to_le_bytes());
        put(20, &self.critical_section_default_timeout.to_le_bytes());
        put(24, &self.de_commit_free_block_threshold.to_le_bytes());
        put(28, &self.de_commit_total_free_threshold.to_le_bytes());
        put(32, &self.lock_prefix_table.to_le_bytes());
        put(36, &self.maximum_allocation_size.to_le_bytes());
        put(40, &self.virtual_memory_threshold.to_le_bytes());
        put(44, &self.process_heap_flags.to_le_bytes());
        put(48, &self.process_affinity_mask.to_le_bytes());
        put(52, &self.csd_version.to_le_bytes());
        put(54, &self.dependent_load_flags.to_le_bytes());
        put(56, &self.edit_list.to_le_bytes());
        put(60, &self.security_cookie.to_le_bytes());
        put(64, &self.se_handler_table.to_le_bytes());
        put(68, &self.se_handler_count.to_le_bytes());
        put(72, &self.guard_cf_check_function_pointer.to_le_bytes());
        put(76, &self.guard_cf_dispatch_function_pointer.to_le_bytes());
        put(80, &self.guard_cf_function_table.to_le_bytes());
        put(84, &self.guard_cf_function_count.to_le_bytes());
        put(88, &self.guard_flags.to_le_bytes());
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

/// `IMAGE_LOAD_CONFIG_DIRECTORY64` (Windows 10 and later).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadConfigDirectory64 {
    /// Size of this structure, in bytes.
    pub size: u32,
    /// Time and date stamp.
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
    /// VA of the lock prefix table (x86 only).
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
    /// VA of the edit list (reserved).
    pub edit_list: u64,
    /// VA of the security cookie.
    pub security_cookie: u64,
    /// VA of the SEH handler table (not used on x64).
    pub se_handler_table: u64,
    /// Number of SEH handlers (not used on x64).
    pub se_handler_count: u64,
    /// VA of the CFG check function pointer.
    pub guard_cf_check_function_pointer: u64,
    /// VA of the CFG dispatch function pointer.
    pub guard_cf_dispatch_function_pointer: u64,
    /// VA of the CFG function table.
    pub guard_cf_function_table: u64,
    /// Number of entries in the CFG function table.
    pub guard_cf_function_count: u64,
    /// CFG flags.
    pub guard_flags: u32,
    /// Bytes of the versioned structure after the fields that this type knows.
    pub trailing_data: Vec<u8>,
}

impl LoadConfigDirectory64 {
    /// Default output size, without the optional CFG fields.
    pub const MIN_SIZE: usize = 112;
    /// Size up to and including `GuardFlags`. Later versioned fields stay as opaque bytes.
    pub const SIZE_WITH_CFG: usize = 148;

    /// Parse a versioned prefix of whole fields. Legacy short records are also valid.
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

    /// Serialize to bytes, up to the value of the `Size` field.
    ///
    /// # Panics
    ///
    /// Panics if the serialized size exceeds `u32` or if the allocation fails. For fallible
    /// serialization, use [`Self::try_to_bytes`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("load-config build failed: use try_to_bytes()")
    }

    /// Serialize to bytes, with checked arithmetic for the versioned size and the trailing size.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the serialized size exceeds `u32` or if the
    /// allocation fails.
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
        let (mut buf, encoded_size) = output_buffer(
            self.size,
            known_size,
            Self::SIZE_WITH_CFG,
            &self.trailing_data,
        )?;
        // The buffer holds at least `MIN_SIZE` bytes. Write a later field only if the buffer
        // holds the complete field.
        let mut put = |offset, bytes: &[u8]| write_field(&mut buf, offset, bytes);
        put(0, &encoded_size.to_le_bytes());
        put(4, &self.time_date_stamp.to_le_bytes());
        put(8, &self.major_version.to_le_bytes());
        put(10, &self.minor_version.to_le_bytes());
        put(12, &self.global_flags_clear.to_le_bytes());
        put(16, &self.global_flags_set.to_le_bytes());
        put(20, &self.critical_section_default_timeout.to_le_bytes());
        put(24, &self.de_commit_free_block_threshold.to_le_bytes());
        put(32, &self.de_commit_total_free_threshold.to_le_bytes());
        put(40, &self.lock_prefix_table.to_le_bytes());
        put(48, &self.maximum_allocation_size.to_le_bytes());
        put(56, &self.virtual_memory_threshold.to_le_bytes());
        put(64, &self.process_affinity_mask.to_le_bytes());
        put(72, &self.process_heap_flags.to_le_bytes());
        put(76, &self.csd_version.to_le_bytes());
        put(78, &self.dependent_load_flags.to_le_bytes());
        put(80, &self.edit_list.to_le_bytes());
        put(88, &self.security_cookie.to_le_bytes());
        put(96, &self.se_handler_table.to_le_bytes());
        put(104, &self.se_handler_count.to_le_bytes());
        put(112, &self.guard_cf_check_function_pointer.to_le_bytes());
        put(120, &self.guard_cf_dispatch_function_pointer.to_le_bytes());
        put(128, &self.guard_cf_function_table.to_le_bytes());
        put(136, &self.guard_cf_function_count.to_le_bytes());
        put(144, &self.guard_flags.to_le_bytes());
        Ok(buf)
    }

    /// Check if CFG is enabled.
    #[must_use]
    pub fn has_cfg(&self) -> bool {
        self.guard_cf_function_table != 0 || self.guard_flags != 0
    }
}

/// Load configuration directory, in the 32-bit or the 64-bit layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadConfigDirectory {
    /// PE32 `IMAGE_LOAD_CONFIG_DIRECTORY32`.
    Config32(LoadConfigDirectory32),
    /// PE32+ `IMAGE_LOAD_CONFIG_DIRECTORY64`.
    Config64(LoadConfigDirectory64),
}

impl LoadConfigDirectory {
    /// Parse the 32-bit or the 64-bit layout. `is_64bit` selects the layout.
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

    /// Serialize to bytes, up to the value of the `Size` field.
    ///
    /// # Panics
    ///
    /// Panics if the serialized size exceeds `u32` or if the allocation fails. For fallible
    /// serialization, use [`Self::try_to_bytes`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("load-config build failed: use try_to_bytes()")
    }

    /// Serialize to bytes, with checked arithmetic for the versioned size and the trailing size.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the serialized size exceeds `u32` or if the
    /// allocation fails.
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

/// `GuardFlags` values (`IMAGE_GUARD_*`) for the load configuration directory.
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
    /// `IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT`: module contains suppressed-export
    /// information.
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

/// Builder for load configuration directories.
///
/// A load configuration directory contains security features, for example `SafeSEH` and CFG.
/// This builder makes it easier to create and change these complex structures.
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
    /// `true` for a 64-bit PE.
    is_64bit: bool,
}

impl LoadConfigBuilder {
    /// Create a new load configuration builder.
    #[must_use]
    pub fn new(is_64bit: bool) -> Self {
        Self { is_64bit }
    }

    /// Build a basic load configuration directory with only a security cookie.
    ///
    /// `security_cookie_va` is the VA of the security cookie.
    ///
    /// Returns the data and its size as `(data, size)`.
    ///
    /// # Panics
    ///
    /// Panics if the builder is for PE32 and the cookie VA exceeds `u32`. For fallible
    /// building, use [`Self::try_build_with_cookie`].
    #[must_use]
    pub fn build_with_cookie(&self, security_cookie_va: u64) -> (Vec<u8>, u32) {
        self.try_build_with_cookie(security_cookie_va)
            .expect("load-config build failed: use try_build_with_cookie()")
    }

    /// Build a basic load configuration directory. PE32 values are not truncated.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the builder is for PE32 and
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
    /// Returns the data and its size as `(data, size)`.
    ///
    /// # Panics
    ///
    /// Panics in these conditions:
    /// - The bitness of the directory is not the bitness of the builder.
    /// - The size of the directory exceeds `u32`.
    /// - The allocation fails.
    ///
    /// For fallible building, use [`Self::try_build`].
    #[must_use]
    pub fn build(&self, config: &LoadConfigDirectory) -> (Vec<u8>, u32) {
        self.try_build(config)
            .expect("load-config build failed: use try_build()")
    }

    /// Build from an existing directory. The directory must have the PE width of the builder.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error in these conditions:
    /// - The bitness of the directory is not the bitness of the builder.
    /// - The serialized size exceeds `u32`.
    /// - The allocation fails.
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

    /// Build a load configuration directory with CFG (Control Flow Guard) settings.
    ///
    /// Returns the data and its size as `(data, size)`.
    ///
    /// # Panics
    ///
    /// Panics if the builder is for PE32 and a value in `cfg` exceeds `u32`. For fallible
    /// building, use [`Self::try_build_with_cfg`].
    #[must_use]
    pub fn build_with_cfg(&self, cfg: &CfgSettings) -> (Vec<u8>, u32) {
        self.try_build_with_cfg(cfg)
            .expect("load-config build failed: use try_build_with_cfg()")
    }

    /// Build a load configuration directory with CFG enabled. PE32 values are checked.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the builder is for PE32 and a VA or the
    /// function count in `cfg` does not fit in `u32`.
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

    /// Calculate the size of the load configuration data.
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

    #[test]
    fn serialization_keeps_trailing_data_and_declared_size() {
        let config32 = LoadConfigDirectory32 {
            size: 70,
            security_cookie: 0x0040_1000,
            trailing_data: vec![0xAA, 0xBB],
            ..Default::default()
        };
        let bytes32 = config32.try_to_bytes().expect("a small PE32 record");
        assert_eq!(bytes32.len(), LoadConfigDirectory32::SIZE_WITH_CFG + 2);
        assert_eq!(bytes32[92..], [0xAA, 0xBB]);
        let parsed32 = LoadConfigDirectory32::parse(&bytes32).expect("serialized PE32 record");
        assert_eq!(parsed32.trailing_data, config32.trailing_data);
        assert_eq!(parsed32.security_cookie, config32.security_cookie);

        let config64 = LoadConfigDirectory64 {
            size: 200,
            guard_flags: guard_flags::CF_INSTRUMENTED,
            trailing_data: vec![0xCC],
            ..Default::default()
        };
        let bytes64 = config64.try_to_bytes().expect("a small PE32+ record");
        assert_eq!(bytes64.len(), 200);
        assert_eq!(bytes64[148], 0xCC);
        assert!(bytes64[149..].iter().all(|&byte| byte == 0));
        let parsed64 = LoadConfigDirectory64::parse(&bytes64).expect("serialized PE32+ record");
        assert_eq!(parsed64.guard_flags, config64.guard_flags);
        assert_eq!(parsed64.size, 200);
    }

    /// On a 32-bit target, a `Size` of `u32::MAX` exceeds `isize::MAX`. Before the fix,
    /// `vec!` panicked with a capacity overflow.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn serialization_reports_unallocatable_size() {
        let config32 = LoadConfigDirectory32 {
            size: u32::MAX,
            ..Default::default()
        };
        assert!(config32.try_to_bytes().is_err());
        let config64 = LoadConfigDirectory64 {
            size: u32::MAX,
            ..Default::default()
        };
        assert!(config64.try_to_bytes().is_err());
        assert!(
            LoadConfigBuilder::new(false)
                .try_build(&LoadConfigDirectory::Config32(config32))
                .is_err()
        );
    }
}
