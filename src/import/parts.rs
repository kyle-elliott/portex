//! Split a table buffer into parts that `nostdio` cursors write.

use nostdio::{Cursor, Seek};

use crate::{Error, Result};

/// Split `data` into consecutive parts that start at the offsets in `starts`, and return a
/// `nostdio` cursor over each part. The first offset must be 0.
///
/// The import and delay-import builders write each part of a table through its own cursor. A
/// write past the end of a part thus returns an error and does not change the next part.
///
/// # Errors
///
/// Returns an invalid-data-directory error if the first offset is not 0, or if the offsets do
/// not ascend to at most `data.len()`.
pub(crate) fn split_parts<const N: usize>(
    data: &mut [u8],
    starts: [usize; N],
) -> Result<[Cursor<&mut [u8]>; N]> {
    let error = || Error::invalid_data_directory("import table parts are not in order");
    let mut lengths = [0usize; N];
    let mut end = data.len();
    for (length, start) in lengths.iter_mut().zip(starts).rev() {
        *length = end.checked_sub(start).ok_or_else(error)?;
        end = start;
    }
    if end != 0 {
        return Err(error());
    }

    let mut rest = data;
    Ok(core::array::from_fn(|index| {
        // The lengths add up to `data.len()`, so each split is in bounds.
        let (part, tail) = core::mem::take(&mut rest).split_at_mut(lengths[index]);
        rest = tail;
        Cursor::new(part)
    }))
}

/// Move `cursor` forward to the next even position, if it is at an odd position.
///
/// # Errors
///
/// Returns an I/O error if the new position overflows.
pub(crate) fn skip_to_even(cursor: &mut Cursor<&mut [u8]>) -> Result<()> {
    if cursor.position() & 1 == 1 {
        cursor.seek_relative(1)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use nostdio::Write;

    use super::*;

    #[test]
    fn split_parts_gives_each_part_its_own_cursor() {
        let mut data = [0u8; 6];
        let [mut first, mut second, third] = split_parts(&mut data, [0, 2, 5]).unwrap();
        first.write_all(&[1, 2]).unwrap();
        // A write past the end of a part fails and leaves the next part unchanged.
        assert!(first.write_all(&[3]).is_err());
        second.write_all(&[4, 5, 6]).unwrap();
        assert_eq!(third.get_ref().len(), 1);
        assert_eq!(data, [1, 2, 4, 5, 6, 0]);
    }

    #[test]
    fn split_parts_rejects_bad_offsets() {
        let mut data = [0u8; 4];
        assert!(split_parts(&mut data, [1, 2]).is_err());
        assert!(split_parts(&mut data, [0, 3, 2]).is_err());
        assert!(split_parts(&mut data, [0, 5]).is_err());
    }

    #[test]
    fn skip_to_even_moves_only_from_odd_positions() {
        let mut data = [0u8; 4];
        let mut cursor = Cursor::new(&mut data[..]);
        skip_to_even(&mut cursor).unwrap();
        assert_eq!(cursor.position(), 0);
        cursor.seek_relative(1).unwrap();
        skip_to_even(&mut cursor).unwrap();
        assert_eq!(cursor.position(), 2);
    }
}
