//! Low-level byte-reading utilities for little-endian structure access.
//!
//! These functions are the foundation of the zero-copy parsing approach.
//! Each compiles to a single `mov` instruction on x86 targets.
//!
//! All functions return `None` if the requested read would exceed the
//! buffer length, so callers never need to pre-validate bounds.

/// Reads a little-endian `u16` from `data` at the given byte `offset`.
///
/// Returns `None` if `offset + 2 > data.len()`.
#[inline(always)]
pub(crate) fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: &[u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(*bytes))
}

/// Reads a little-endian `u32` from `data` at the given byte `offset`.
///
/// Returns `None` if `offset + 4 > data.len()`.
#[inline(always)]
pub(crate) fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: &[u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(*bytes))
}

/// Reads a little-endian `i16` from `data` at the given byte `offset`.
///
/// Returns `None` if `offset + 2 > data.len()`.
#[inline(always)]
pub(crate) fn read_i16_le(data: &[u8], offset: usize) -> Option<i16> {
    let bytes: &[u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(i16::from_le_bytes(*bytes))
}

/// Reads a little-endian `i32` from `data` at the given byte `offset`.
///
/// Returns `None` if `offset + 4 > data.len()`.
#[inline(always)]
pub(crate) fn read_i32_le(data: &[u8], offset: usize) -> Option<i32> {
    let bytes: &[u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(i32::from_le_bytes(*bytes))
}

/// Reads a little-endian `u64` from `data` at the given byte `offset`.
///
/// Returns `None` if `offset + 8 > data.len()`.
#[inline(always)]
pub(crate) fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: &[u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(*bytes))
}

/// Reads a little-endian `i64` from `data` at the given byte `offset`.
///
/// Returns `None` if `offset + 8 > data.len()`.
#[inline(always)]
pub(crate) fn read_i64_le(data: &[u8], offset: usize) -> Option<i64> {
    let bytes: &[u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(i64::from_le_bytes(*bytes))
}

/// Reads a little-endian `f32` from `data` at the given byte `offset`.
///
/// Returns `None` if `offset + 4 > data.len()`.
#[inline(always)]
pub(crate) fn read_f32_le(data: &[u8], offset: usize) -> Option<f32> {
    let bytes: &[u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(f32::from_le_bytes(*bytes))
}

/// Reads a little-endian `f64` from `data` at the given byte `offset`.
///
/// Returns `None` if `offset + 8 > data.len()`.
#[inline(always)]
pub(crate) fn read_f64_le(data: &[u8], offset: usize) -> Option<f64> {
    let bytes: &[u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(f64::from_le_bytes(*bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u16_basic() {
        assert_eq!(read_u16_le(&[0x34, 0x12], 0), Some(0x1234));
    }

    #[test]
    fn u32_basic() {
        assert_eq!(read_u32_le(&[0x78, 0x56, 0x34, 0x12], 0), Some(0x12345678));
    }

    #[test]
    fn i16_negative() {
        assert_eq!(read_i16_le(&[0x70, 0xFF], 0), Some(-144));
    }

    #[test]
    fn i32_negative() {
        assert_eq!(read_i32_le(&[0xFE, 0xFF, 0xFF, 0xFF], 0), Some(-2));
    }

    #[test]
    fn u64_basic() {
        assert_eq!(
            read_u64_le(&[0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12], 0),
            Some(0x1234567890ABCDEF)
        );
    }

    #[test]
    fn i64_negative() {
        assert_eq!(
            read_i64_le(&[0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], 0),
            Some(-2)
        );
    }

    #[test]
    fn f32_basic() {
        let val = read_f32_le(&1.5_f32.to_le_bytes(), 0);
        assert_eq!(val, Some(1.5));
    }

    #[test]
    fn f64_basic() {
        let val = read_f64_le(&2.5_f64.to_le_bytes(), 0);
        assert_eq!(val, Some(2.5));
    }

    #[test]
    fn out_of_bounds_returns_none() {
        assert_eq!(read_u16_le(&[0x01], 0), None);
        assert_eq!(read_u32_le(&[0x01, 0x02, 0x03], 0), None);
        assert_eq!(read_u16_le(&[0x01, 0x02], 1), None);
        assert_eq!(read_u64_le(&[0x01, 0x02, 0x03, 0x04], 0), None);
    }
}
