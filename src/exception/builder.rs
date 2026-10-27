//! Builder for the x64 exception directory.

use super::{ExceptionDirectory, RuntimeFunction};
use crate::prelude::*;
use crate::{Error, Result};

/// Builder for exception directories (.pdata).
///
/// Exception directories contain runtime function entries for x64 SEH.
/// This builder helps create and manage these entries.
///
/// # Example
///
/// ```
/// use portex::exception::ExceptionBuilder;
///
/// let mut builder = ExceptionBuilder::new();
///
/// // Add functions with their unwind info RVAs
/// builder.add_function(0x1000, 0x1100, 0x3000);
/// builder.add_function(0x1200, 0x1400, 0x3100);
///
/// let (data, size) = builder.build();
/// assert_eq!(size, 24); // 2 functions * 12 bytes each
/// ```
#[derive(Debug, Clone, Default)]
pub struct ExceptionBuilder {
    /// The exception directory being built.
    directory: ExceptionDirectory,
}

impl ExceptionBuilder {
    /// Create a new exception builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from an existing exception directory.
    #[must_use]
    pub fn from_directory(directory: ExceptionDirectory) -> Self {
        Self { directory }
    }

    /// Add a runtime function entry.
    ///
    /// # Arguments
    /// * `begin_rva` - RVA of the function start
    /// * `end_rva` - RVA of the function end
    /// * `unwind_info_rva` - RVA of the unwind information
    pub fn add_function(
        &mut self,
        begin_rva: u32,
        end_rva: u32,
        unwind_info_rva: u32,
    ) -> &mut Self {
        self.directory
            .add_function(begin_rva, end_rva, unwind_info_rva);
        self
    }

    /// Build the exception directory.
    ///
    /// Returns (data, size) where:
    /// - `data` is the raw bytes to write to the section
    /// - `size` is the total size of the exception directory
    ///
    /// # Panics
    /// Panics if [`Self::try_build`] fails.
    pub fn build(&mut self) -> (Vec<u8>, u32) {
        self.try_build()
            .expect("exception-directory build failed: use try_build()")
    }

    /// Sort and build the exception directory, returning `(data, size)`.
    ///
    /// # Errors
    /// Returns an error if the directory fails validation.
    pub fn try_build(&mut self) -> Result<(Vec<u8>, u32)> {
        // Sort by begin address (required for binary search)
        self.directory.sort();
        let data = self.directory.try_to_bytes()?;
        let size = u32::try_from(data.len())
            .map_err(|_| Error::invalid_data_directory("exception table size exceeds u32"))?;
        Ok((data, size))
    }

    /// Build from the existing directory without modification.
    ///
    /// # Panics
    /// Panics if [`Self::try_build_from`] fails.
    #[must_use]
    pub fn build_from(directory: &ExceptionDirectory) -> (Vec<u8>, u32) {
        Self::try_build_from(directory)
            .expect("exception-directory build failed: use try_build_from()")
    }

    /// Sort a copy of `directory` and build it, returning `(data, size)`.
    ///
    /// # Errors
    /// Returns an error if the directory fails validation.
    pub fn try_build_from(directory: &ExceptionDirectory) -> Result<(Vec<u8>, u32)> {
        let mut dir = directory.clone();
        dir.sort();
        let data = dir.try_to_bytes()?;
        let size = u32::try_from(data.len())
            .map_err(|_| Error::invalid_data_directory("exception table size exceeds u32"))?;
        Ok((data, size))
    }

    /// Get the number of functions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.directory.len()
    }

    /// Check if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.directory.is_empty()
    }

    /// Calculate the size needed for the exception directory.
    ///
    /// # Panics
    /// Panics if [`Self::try_calculate_size`] fails.
    #[must_use]
    pub fn calculate_size(num_functions: usize) -> usize {
        Self::try_calculate_size(num_functions)
            .expect("exception-directory size overflow: use try_calculate_size()")
    }

    /// Calculate the size needed for `num_functions` entries.
    ///
    /// # Errors
    /// Returns an error if the size overflows or exceeds `u32`.
    pub fn try_calculate_size(num_functions: usize) -> Result<usize> {
        let size = num_functions
            .checked_mul(RuntimeFunction::SIZE)
            .ok_or_else(|| Error::invalid_data_directory("exception table size overflow"))?;
        u32::try_from(size)
            .map_err(|_| Error::invalid_data_directory("exception table size exceeds u32"))?;
        Ok(size)
    }
}
