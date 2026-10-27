//! Write position for the import table builders.

use crate::{Error, Result};

/// A write position in a zeroed output buffer.
///
/// [`super::ImportTableBuilder`] and [`crate::delay_import::DelayImportBuilder`]
/// use one `Cursor` for each part of the table. Each operation checks the
/// bounds. A layout error thus gives an [`Error`] and not a panic.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Cursor {
    offset: usize,
}

impl Cursor {
    /// Make a cursor at byte `offset` of the buffer.
    pub(crate) fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Return the byte offset of the cursor in the buffer.
    pub(crate) fn offset(self) -> usize {
        self.offset
    }

    /// Copy `bytes` into `data` at the cursor, then move the cursor past them.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::BufferTooSmall` if `bytes` do not fit in `data` at
    /// the cursor. Returns `ErrorKind::InvalidDataDirectory` if the new
    /// offset overflows `usize`.
    pub(crate) fn put(&mut self, data: &mut [u8], bytes: &[u8]) -> Result<()> {
        let end = self.end(bytes.len())?;
        let len = data.len();
        let target = data
            .get_mut(self.offset..end)
            .ok_or_else(|| Error::buffer_too_small(end, len))?;
        target.copy_from_slice(bytes);
        self.offset = end;
        Ok(())
    }

    /// Move the cursor `len` bytes forward. The bytes that the cursor skips
    /// keep their value.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::InvalidDataDirectory` if the new offset overflows
    /// `usize`.
    pub(crate) fn skip(&mut self, len: usize) -> Result<()> {
        self.offset = self.end(len)?;
        Ok(())
    }

    /// Move the cursor forward to the next even offset.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::InvalidDataDirectory` if the new offset overflows
    /// `usize`.
    pub(crate) fn align_even(&mut self) -> Result<()> {
        self.skip(self.offset & 1)
    }

    /// Return the offset `len` bytes after the cursor.
    fn end(self, len: usize) -> Result<usize> {
        self.offset
            .checked_add(len)
            .ok_or_else(|| Error::invalid_data_directory("import table offset overflow"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_past_end_is_an_error() {
        let mut data = [0u8; 4];
        let mut cursor = Cursor::new(2);
        assert!(cursor.put(&mut data, &[1, 2, 3]).is_err());
        assert_eq!(cursor.offset(), 2);
        cursor.put(&mut data, &[1, 2]).unwrap();
        assert_eq!(data, [0, 0, 1, 2]);
        assert_eq!(cursor.offset(), 4);
    }

    #[test]
    fn skip_overflow_is_an_error() {
        let mut cursor = Cursor::new(usize::MAX);
        assert!(cursor.skip(1).is_err());
        assert!(Cursor::new(usize::MAX).align_even().is_err());
    }

    #[test]
    fn align_even_pads_odd_offsets_only() {
        let mut cursor = Cursor::new(3);
        cursor.align_even().unwrap();
        assert_eq!(cursor.offset(), 4);
        cursor.align_even().unwrap();
        assert_eq!(cursor.offset(), 4);
    }
}
