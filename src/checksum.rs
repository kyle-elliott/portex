//! PE checksum calculation.
//!
//! The PE checksum lets a tool verify the integrity of a PE file. Drivers and system files
//! usually have a checksum.

/// Calculate the PE checksum for a file.
///
/// `checksum_offset` is the file offset of the `CheckSum` field. The algorithm:
///
/// 1. Add all 16-bit words. Use 32-bit arithmetic with an end-around carry.
/// 2. Skip the 4-byte checksum field at `checksum_offset`.
/// 3. Fold the result to 16 bits.
/// 4. Add the file size (modulo 2^32).
#[must_use]
pub fn calculate_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    // Folding after every addition keeps `sum` within 16 bits, so adding a
    // 16-bit word never overflows a `u32`.
    let mut sum: u32 = 0;
    let len = data.len();

    // Process 16-bit words, each paired with its file offset.
    let skip = checksum_offset..checksum_offset.saturating_add(4);
    let (words, tail) = data.as_chunks::<2>();
    for (offset, word) in (0..len).step_by(2).zip(words) {
        // Skip the checksum field (4 bytes at checksum_offset).
        if skip.contains(&offset) {
            continue;
        }
        sum = fold_carry(sum + u32::from(u16::from_le_bytes(*word)));
    }

    // Add the odd byte at the end.
    if let [byte] = tail {
        sum = fold_carry(sum + u32::from(*byte));
    }

    // Add the file size. The algorithm uses only the low 32 bits.
    let [b0, b1, b2, b3, ..] = len.to_le_bytes();
    let size_low = u32::from_le_bytes([b0, b1, b2, b3]);
    sum.wrapping_add(size_low)
}

/// Fold the carry above bit 15 back into the low 16 bits (end-around carry).
const fn fold_carry(mut sum: u32) -> u32 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum
}

/// Get the file offset of the `CheckSum` field in the optional header
/// (`IMAGE_OPTIONAL_HEADER32` or `IMAGE_OPTIONAL_HEADER64`).
///
/// Returns `None` if the PE is malformed or does not have an optional header.
#[must_use]
pub fn checksum_field_offset(data: &[u8]) -> Option<usize> {
    // The DOS header field e_lfanew is at file offset 0x3C.
    let e_lfanew = data.get(0x3C..)?.first_chunk::<4>()?;
    let pe_offset = usize::try_from(u32::from_le_bytes(*e_lfanew)).ok()?;

    // Skip the PE signature (4) and the COFF header (20). The checksum is at offset 64 in the
    // optional header.
    let checksum_offset = pe_offset.checked_add(4 + 20 + 64)?;

    if checksum_offset.checked_add(4)? > data.len() {
        return None;
    }

    Some(checksum_offset)
}

/// Calculate and return the checksum for PE data.
///
/// Returns `None` if this function cannot find the file offset of the checksum field.
#[must_use]
pub fn compute_pe_checksum(data: &[u8]) -> Option<u32> {
    let offset = checksum_field_offset(data)?;
    Some(calculate_checksum(data, offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::vec;

    #[test]
    fn test_checksum_field_offset() {
        // Minimal PE-like structure
        let mut data = vec![0u8; 256];
        // DOS signature
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew pointing to PE header at 0x80
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE signature
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;

        let offset = checksum_field_offset(&data);
        // PE offset (0x80) + signature (4) + COFF (20) + checksum offset in optional (64)
        assert_eq!(offset, Some(0x80 + 4 + 20 + 64));
    }

    #[test]
    fn test_calculate_checksum() {
        // Simple test with known data
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        // No checksum field to skip (use offset beyond data)
        let checksum = calculate_checksum(&data, 1000);
        // Sum of words: 0x0201 + 0x0403 + 0x0605 + 0x0807 = 0x1410
        // Plus file size: 0x1410 + 8 = 0x1418
        assert_eq!(checksum, 0x1418);
    }
}
