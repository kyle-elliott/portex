//! Exception directory (.pdata) parsing and building.
//!
//! The exception directory contains runtime function entries used for
//! structured exception handling (SEH) and stack unwinding on x64.

mod arm;
mod builder;
mod table;
mod unwind;
mod x64;

pub use arm::{PackedExceptionDirectory, PackedRuntimeFunction};
pub use builder::ExceptionBuilder;
pub use table::ExceptionTable;
pub use unwind::{
    UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER, UNW_FLAG_NHANDLER, UNW_FLAG_UHANDLER, UnwindCode,
    UnwindInfo, UnwindOpCode,
};
pub use x64::{ExceptionDirectory, RuntimeFunction};
