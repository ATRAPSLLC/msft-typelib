//! Error types for MSFT type library parsing.
//!
//! All errors are non-fatal data-validation failures.  Because the parser
//! is zero-copy and does not allocate, I/O errors are the caller's
//! responsibility (load the file, then pass `&[u8]` to
//! [`TypeLib::parse`](crate::TypeLib::parse)).

use std::fmt;

/// Errors that can occur when parsing an MSFT type library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The input buffer is too short for the expected structure.
    TooShort {
        /// Minimum number of bytes required.
        expected: usize,
        /// Actual number of bytes available.
        actual: usize,
        /// Human-readable name of the structure being parsed.
        context: &'static str,
    },
    /// The file does not start with the expected `"MSFT"` magic bytes.
    BadMagic {
        /// Expected magic value (`0x5446534D`).
        expected: u32,
        /// Actual value found at offset 0.
        got: u32,
    },
    /// A TypeInfo index is outside the valid range `0..typeinfo_count`.
    TypeInfoOutOfRange {
        /// The requested index.
        index: usize,
        /// Total number of TypeInfo entries in this library.
        count: usize,
    },
    /// A required field or offset could not be read from the binary data.
    ///
    /// This typically indicates a truncated or corrupt type library.
    InvalidData {
        /// Human-readable description of what went wrong.
        context: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooShort {
                expected,
                actual,
                context,
            } => write!(
                f,
                "{context}: expected at least {expected} bytes, got {actual}"
            ),
            Error::BadMagic { expected, got } => {
                write!(f, "bad magic: expected 0x{expected:08X}, got 0x{got:08X}")
            }
            Error::TypeInfoOutOfRange { index, count } => {
                write!(f, "typeinfo index {index} out of range (count: {count})")
            }
            Error::InvalidData { context } => {
                write!(f, "invalid data: {context}")
            }
        }
    }
}

impl std::error::Error for Error {}
