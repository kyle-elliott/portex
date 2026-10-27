//! Security directory (Authenticode) parsing.
//!
//! The security directory contains `WIN_CERTIFICATE` structures for code signing.
//! Unlike other data directories, this one uses a **file offset** (not RVA).
//!
//! # Examples
//!
//! ```no_run
//! use portex::PeFile;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeFile::parse(file_bytes)?;
//!
//! if let Some(certs) = pe.security()? {
//!     for cert in &certs.certificates {
//!         println!("Certificate type: {:?}, revision: {:?}",
//!             cert.certificate_type, cert.revision);
//!         println!("  Data length: {} bytes", cert.data.len());
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```

use crate::prelude::*;
use crate::{Error, Result};

/// `WIN_CERTIFICATE` revision values (`wRevision`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateRevision {
    /// `WIN_CERT_REVISION_1_0`
    Revision1,
    /// `WIN_CERT_REVISION_2_0`
    Revision2,
    /// Revision not known to this version of the crate.
    Unknown(u16),
}

impl CertificateRevision {
    /// Convert from raw u16.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        match value {
            0x0100 => Self::Revision1,
            0x0200 => Self::Revision2,
            other => Self::Unknown(other),
        }
    }

    /// Convert to the raw `wRevision` value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Revision1 => 0x0100,
            Self::Revision2 => 0x0200,
            Self::Unknown(value) => value,
        }
    }
}

/// `WIN_CERTIFICATE` type values (`wCertificateType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateType {
    /// `WIN_CERT_TYPE_X509` - X.509 certificate
    X509,
    /// `WIN_CERT_TYPE_PKCS_SIGNED_DATA` - PKCS#7 `SignedData`
    PkcsSignedData,
    /// `WIN_CERT_TYPE_RESERVED_1`
    Reserved1,
    /// `WIN_CERT_TYPE_TS_STACK_SIGNED` - Terminal Server Protocol Stack
    TsStackSigned,
    /// Certificate type not known to this version of the crate.
    Unknown(u16),
}

impl CertificateType {
    /// Convert from raw u16.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        match value {
            0x0001 => Self::X509,
            0x0002 => Self::PkcsSignedData,
            0x0003 => Self::Reserved1,
            0x0004 => Self::TsStackSigned,
            other => Self::Unknown(other),
        }
    }

    /// Convert to the raw `wCertificateType` value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::X509 => 0x0001,
            Self::PkcsSignedData => 0x0002,
            Self::Reserved1 => 0x0003,
            Self::TsStackSigned => 0x0004,
            Self::Unknown(value) => value,
        }
    }
}

/// `WIN_CERTIFICATE` structure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "certificate_type mirrors the spec field wCertificateType; `type` is a keyword"
)]
pub struct Certificate {
    /// Total length including the header but excluding alignment padding.
    pub length: u32,
    /// Certificate revision.
    pub revision: CertificateRevision,
    /// Certificate type.
    pub certificate_type: CertificateType,
    /// Raw certificate data (without header).
    pub data: Vec<u8>,
}

impl Certificate {
    /// Minimum header size (length + revision + type).
    pub const HEADER_SIZE: usize = 8;

    /// Parse a single certificate from a byte slice.
    /// Returns the certificate and number of bytes consumed (including padding).
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::BufferTooSmall`](crate::error::ErrorKind::BufferTooSmall)
    /// if `data` is shorter than the 8-byte header, and
    /// [`ErrorKind::InvalidDataDirectory`](crate::error::ErrorKind::InvalidDataDirectory)
    /// if `dwLength` is smaller than the header or the (8-byte aligned) length
    /// exceeds `data`.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        let Some((header, _)) = data.split_first_chunk::<{ Self::HEADER_SIZE }>() else {
            return Err(Error::buffer_too_small(Self::HEADER_SIZE, data.len()));
        };
        let [l0, l1, l2, l3, r0, r1, t0, t1] = *header;
        let length_u32 = u32::from_le_bytes([l0, l1, l2, l3]);
        let length = usize::try_from(length_u32)
            .map_err(|_| Error::invalid_data_directory("certificate length exceeds usize"))?;
        let revision = CertificateRevision::from_u16(u16::from_le_bytes([r0, r1]));
        let certificate_type = CertificateType::from_u16(u16::from_le_bytes([t0, t1]));

        let Some(cert_data) = data.get(Self::HEADER_SIZE..length).map(<[u8]>::to_vec) else {
            return Err(Error::invalid_data_directory(format!(
                "invalid certificate length: {} (available: {})",
                length,
                data.len()
            )));
        };

        // Certificates are 8-byte aligned
        let padded_length = length
            .checked_add(7)
            .map(|value| value & !7)
            .ok_or_else(|| Error::invalid_data_directory("certificate alignment overflow"))?;
        if padded_length > data.len() {
            return Err(Error::invalid_data_directory(format!(
                "aligned certificate length {} exceeds the remaining directory size {}",
                padded_length,
                data.len()
            )));
        }

        Ok((
            Self {
                length: length_u32,
                revision,
                certificate_type,
                data: cert_data,
            },
            padded_length,
        ))
    }
}

/// Security directory containing all certificates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityDirectory {
    /// List of certificates.
    pub certificates: Vec<Certificate>,
}

impl SecurityDirectory {
    /// Parse all certificates from the security directory data.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidDataDirectory`](crate::error::ErrorKind::InvalidDataDirectory)
    /// if trailing bytes cannot hold a certificate header, and propagates any
    /// error from [`Certificate::parse`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut certificates = Vec::new();
        let mut rest = data;

        while !rest.is_empty() {
            if rest.len() < Certificate::HEADER_SIZE {
                return Err(Error::invalid_data_directory(format!(
                    "{} trailing bytes remain after the final certificate",
                    rest.len()
                )));
            }

            let (cert, consumed) = Certificate::parse(rest)?;
            certificates.push(cert);
            // `Certificate::parse` returns `consumed <= rest.len()`.
            rest = rest.get(consumed..).unwrap_or_default();
        }

        Ok(Self { certificates })
    }
}

/// Builder for serializing security certificates.
///
/// **Note:** The security directory is special - it uses FILE OFFSETS (not RVAs)
/// and stores certificates in the overlay area after all section data.
/// This builder only creates the certificate data; you must append it to
/// the file manually and update the data directory pointer.
#[derive(Debug, Default)]
pub struct SecurityBuilder;

impl SecurityBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Calculate the total size needed for all certificates.
    ///
    /// Each certificate is 8-byte aligned.
    ///
    /// # Panics
    ///
    /// Panics whenever [`Self::try_calculate_size`] would return an error.
    #[must_use]
    pub fn calculate_size(directory: &SecurityDirectory) -> usize {
        Self::try_calculate_size(directory)
            .expect("certificate table size overflow: use try_calculate_size()")
    }

    /// Calculate the table size with checked `WIN_CERTIFICATE` lengths.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidDataDirectory`](crate::error::ErrorKind::InvalidDataDirectory)
    /// if any certificate length or the total table size overflows or exceeds
    /// `u32`.
    pub fn try_calculate_size(directory: &SecurityDirectory) -> Result<usize> {
        let size = directory
            .certificates
            .iter()
            .try_fold(0usize, |total, certificate| {
                let length = Certificate::HEADER_SIZE
                    .checked_add(certificate.data.len())
                    .ok_or_else(|| Error::invalid_data_directory("certificate length overflow"))?;
                u32::try_from(length).map_err(|_| {
                    Error::invalid_data_directory("WIN_CERTIFICATE length exceeds u32")
                })?;
                let padded = length
                    .checked_add(7)
                    .map(|value| value & !7)
                    .ok_or_else(|| {
                        Error::invalid_data_directory("certificate alignment overflow")
                    })?;
                total
                    .checked_add(padded)
                    .ok_or_else(|| Error::invalid_data_directory("certificate-table size overflow"))
            })?;
        u32::try_from(size)
            .map_err(|_| Error::invalid_data_directory("certificate table exceeds u32"))?;
        Ok(size)
    }

    /// Build the security directory data.
    ///
    /// Returns the raw bytes to be appended to the file's overlay area.
    /// After appending, update the Security data directory with:
    /// - `virtual_address` = file offset where data was appended
    /// - size = returned size
    ///
    /// # Panics
    ///
    /// Panics whenever [`Self::try_build`] would return an error.
    #[must_use]
    pub fn build(directory: &SecurityDirectory) -> Vec<u8> {
        Self::try_build(directory)
            .expect("certificate build failed: use try_build() for fallible serialization")
    }

    /// Build the security directory with checked lengths and alignments.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidDataDirectory`](crate::error::ErrorKind::InvalidDataDirectory)
    /// if any certificate length or the total table size overflows or exceeds
    /// `u32`.
    pub fn try_build(directory: &SecurityDirectory) -> Result<Vec<u8>> {
        if directory.certificates.is_empty() {
            return Ok(Vec::new());
        }

        let total_size = Self::try_calculate_size(directory)?;
        let mut data = Vec::with_capacity(total_size);

        for cert in &directory.certificates {
            // Write length (header + data, unpadded)
            let cert_length_u32 = Certificate::HEADER_SIZE
                .checked_add(cert.data.len())
                .and_then(|length| u32::try_from(length).ok())
                .ok_or_else(|| Error::invalid_data_directory("certificate length exceeds u32"))?;
            data.extend_from_slice(&cert_length_u32.to_le_bytes());
            data.extend_from_slice(&cert.revision.as_u16().to_le_bytes());
            data.extend_from_slice(&cert.certificate_type.as_u16().to_le_bytes());
            data.extend_from_slice(&cert.data);

            // Pad to the next 8-byte aligned position. Each certificate starts
            // at an aligned position, so this aligns the certificate length.
            let padded_end = data
                .len()
                .checked_add(7)
                .map(|value| value & !7)
                .ok_or_else(|| Error::invalid_data_directory("certificate alignment overflow"))?;
            data.resize(padded_end, 0);
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_header_size() {
        assert_eq!(Certificate::HEADER_SIZE, 8);
    }

    #[test]
    fn test_certificate_revision() {
        assert_eq!(
            CertificateRevision::from_u16(0x0100),
            CertificateRevision::Revision1
        );
        assert_eq!(
            CertificateRevision::from_u16(0x0200),
            CertificateRevision::Revision2
        );
        assert_eq!(
            CertificateRevision::from_u16(0x0300),
            CertificateRevision::Unknown(0x0300)
        );
    }

    #[test]
    fn test_certificate_type() {
        assert_eq!(
            CertificateType::from_u16(0x0002),
            CertificateType::PkcsSignedData
        );
        assert_eq!(
            CertificateType::from_u16(0x0000),
            CertificateType::Unknown(0x0000)
        );
    }

    #[test]
    fn test_certificate_buffer_too_small() {
        let data = [0u8; 7];
        assert!(Certificate::parse(&data).is_err());
    }

    #[test]
    fn test_builder_empty() {
        let dir = SecurityDirectory::default();
        let data = SecurityBuilder::build(&dir);
        assert_eq!(data, [] as [u8; 0]);
        assert_eq!(SecurityBuilder::calculate_size(&dir), 0);
    }

    #[test]
    fn test_builder_roundtrip() {
        let cert = Certificate {
            length: 0, // Will be calculated by builder
            revision: CertificateRevision::Revision2,
            certificate_type: CertificateType::PkcsSignedData,
            data: vec![0x30, 0x82, 0x01, 0x00], // Fake ASN.1 header
        };

        let dir = SecurityDirectory {
            certificates: vec![cert],
        };

        let data = SecurityBuilder::build(&dir);

        // Parse it back
        let parsed = SecurityDirectory::parse(&data).unwrap();
        assert_eq!(parsed.certificates.len(), 1);
        assert_eq!(
            parsed.certificates[0].revision,
            CertificateRevision::Revision2
        );
        assert_eq!(
            parsed.certificates[0].certificate_type,
            CertificateType::PkcsSignedData
        );
        assert_eq!(parsed.certificates[0].data, vec![0x30, 0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_builder_alignment() {
        // Certificates must be 8-byte aligned
        let cert = Certificate {
            length: 0,
            revision: CertificateRevision::Revision2,
            certificate_type: CertificateType::PkcsSignedData,
            data: vec![1, 2, 3], // 3 bytes data + 8 header = 11, rounds to 16
        };

        let dir = SecurityDirectory {
            certificates: vec![cert],
        };

        let size = SecurityBuilder::calculate_size(&dir);
        assert_eq!(size % 8, 0); // Must be 8-byte aligned
        assert_eq!(size, 16); // 11 rounded up to 16
    }

    #[test]
    fn test_builder_two_certificates_layout() {
        let first = Certificate {
            length: 0,
            revision: CertificateRevision::Revision2,
            certificate_type: CertificateType::PkcsSignedData,
            data: vec![1, 2, 3],
        };
        let second = Certificate {
            length: 0,
            revision: CertificateRevision::Revision1,
            certificate_type: CertificateType::X509,
            data: vec![4; 8],
        };
        let dir = SecurityDirectory {
            certificates: vec![first, second],
        };

        let data = SecurityBuilder::try_build(&dir).unwrap();
        assert_eq!(
            data.len(),
            SecurityBuilder::try_calculate_size(&dir).unwrap()
        );
        assert_eq!(data.len(), 32);
        assert_eq!(&data[0..4], &11u32.to_le_bytes());
        assert_eq!(&data[11..16], &[0; 5]);
        assert_eq!(&data[16..20], &16u32.to_le_bytes());

        let parsed = SecurityDirectory::parse(&data).unwrap();
        assert_eq!(parsed.certificates.len(), 2);
        assert_eq!(parsed.certificates[1].data, vec![4; 8]);
    }

    #[test]
    fn test_certificate_length_out_of_range() {
        let mut data = [0u8; 16];
        data[0..4].copy_from_slice(&4u32.to_le_bytes());
        assert!(Certificate::parse(&data).is_err());
        data[0..4].copy_from_slice(&17u32.to_le_bytes());
        assert!(Certificate::parse(&data).is_err());
        assert!(SecurityDirectory::parse(&data[..12]).is_err());
    }
}
