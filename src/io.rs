//! Sequential streams and positional image readers.
//!
//! [`nostdio`] supplies the sequential [`Read`], [`Write`] and [`Seek`] traits, which also
//! work in `no_std` builds. The Portex [`ReadAt`] trait stays positional. Thus you can query
//! mapped or remote images without a shared stream cursor.

pub use nostdio::*;

#[cfg(feature = "std")]
pub use crate::reader::FileReader;
pub use crate::reader::{BaseAddressReader, ReadAt, SeekReader, SliceReader, VecReader};
