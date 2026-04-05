//! Decompression support for NSIS installer data.
//!
//! NSIS uses three compression methods: zlib/deflate, bzip2, and LZMA.
//! The header block and individual data files are compressed with a common
//! framing format: a 4-byte length prefix where bit 31 indicates whether
//! the data is compressed.
//!
//! # Compression Modes
//!
//! - **Non-solid**: Header is compressed independently; each data file is a
//!   separate compressed stream with its own length prefix.
//! - **Solid** (`/SOLID`): The entire overlay (header + all data files) is
//!   a single compressed stream.

pub mod bzip2;
pub mod deflate;
pub mod lzma;

use crate::error::Error;

/// Identifies the compression algorithm used by an NSIS installer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    /// Raw deflate (no zlib header).
    Deflate,
    /// NSIS custom bzip2 (no standard `"BZ"` file header).
    Bzip2,
    /// LZMA compression.
    Lzma,
    /// Data is stored uncompressed.
    None,
}

/// Whether the installer uses solid or non-solid compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMode {
    /// All data in a single compressed stream.
    Solid,
    /// Each block compressed independently.
    NonSolid,
}

/// Reads a 4-byte NSIS length prefix.
///
/// Returns `(is_compressed, size)` where:
/// - `is_compressed`: `true` if bit 31 is set (data follows as compressed bytes)
/// - `size`: the lower 31 bits, giving the byte count
///
/// # Errors
///
/// Returns [`Error::TooShort`] if `data.len() < 4`.
pub fn read_length_prefix(data: &[u8]) -> Result<(bool, u32), Error> {
    if data.len() < 4 {
        return Err(Error::TooShort {
            expected: 4,
            actual: data.len(),
            context: "length prefix",
        });
    }
    let raw = crate::util::read_u32_le(data, 0);
    let is_compressed = raw & 0x8000_0000 != 0;
    let size = raw & 0x7FFF_FFFF;
    Ok((is_compressed, size))
}

/// Detects the compression method from the initial bytes of compressed data.
///
/// Detection heuristics:
/// - LZMA: first byte is typically `0x5D` followed by 4-byte dictionary size
/// - bzip2: first byte is `0x31` (NSIS custom bzip2 block header)
/// - Deflate: fallback — try raw deflate decompression
pub fn detect_compression(data: &[u8]) -> CompressionMethod {
    if data.is_empty() {
        return CompressionMethod::None;
    }

    // LZMA: properties byte is typically 0x5D (lc=3, lp=0, pb=2).
    if data[0] == 0x5D && data.len() >= 5 {
        return CompressionMethod::Lzma;
    }

    // NSIS bzip2 starts with a block magic that differs from standard bzip2.
    // The first byte of an NSIS bzip2 stream is '1' (0x31) for the block size digit.
    if data[0] == 0x31 && data.len() >= 4 {
        return CompressionMethod::Bzip2;
    }

    // Default to deflate.
    CompressionMethod::Deflate
}

/// Decompresses a single NSIS data block.
///
/// The `data` should be the compressed bytes (after the 4-byte length prefix).
/// `max_output` limits the decompressed size to prevent memory exhaustion.
///
/// For LZMA streams, `expected_size` provides the exact decompressed size.
/// This is required for solid-mode streams where trailing data follows
/// the LZMA end-of-stream marker. Pass `None` when the size is unknown.
///
/// # Errors
///
/// Returns [`Error::DecompressionFailed`] if decompression fails, or
/// [`Error::UnsupportedCompression`] for [`CompressionMethod::None`] when the
/// data cannot simply be copied.
pub fn decompress_block(
    data: &[u8],
    method: CompressionMethod,
    max_output: usize,
    expected_size: Option<usize>,
) -> Result<Vec<u8>, Error> {
    match method {
        CompressionMethod::Deflate => deflate::decompress_deflate(data, max_output),
        CompressionMethod::Bzip2 => bzip2::decompress_bzip2(data, max_output),
        CompressionMethod::Lzma => lzma::decompress_lzma(data, max_output, expected_size),
        CompressionMethod::None => Ok(data.to_vec()),
    }
}

/// Decompresses the NSIS header block following the FirstHeader.
///
/// This function:
/// 1. Reads the 4-byte length prefix
/// 2. Detects the compression method
/// 3. Decompresses the header data
/// 4. Determines whether this is solid or non-solid compression
///
/// Returns `(decompressed_data, method, mode, header_bytes_consumed)` where
/// `header_bytes_consumed` is the number of bytes from `data` occupied by
/// the compressed (or uncompressed) header. For non-solid mode, the data
/// block starts immediately after these bytes.
///
/// # Arguments
///
/// - `data`: bytes starting immediately after the FirstHeader
/// - `expected_size`: the decompressed header size from `FirstHeader::length_of_header()`
///
/// # Errors
///
/// Returns an error if decompression fails with all supported methods.
pub fn decompress_header(
    data: &[u8],
    expected_size: usize,
) -> Result<(Vec<u8>, CompressionMethod, CompressionMode, usize), Error> {
    // First, try non-solid mode: the header starts with a length prefix.
    // If the length prefix produces values that don't fit, we skip to solid mode.
    let (is_compressed, size) = read_length_prefix(data)?;

    if !is_compressed && (4 + size as usize) <= data.len() {
        // Data is uncompressed — just take the raw bytes.
        let size = size as usize;
        return Ok((
            data[4..4 + size].to_vec(),
            CompressionMethod::None,
            CompressionMode::NonSolid,
            4 + size,
        ));
    }

    let compressed_size = size as usize;
    let non_solid_viable = is_compressed && data.len() >= 4 + compressed_size;
    let compressed_data = if non_solid_viable {
        &data[4..4 + compressed_size]
    } else {
        &[] as &[u8]
    };
    let non_solid_consumed = 4 + compressed_size;

    // Try to detect and decompress with non-solid framing.
    // In non-solid mode the length prefix cleanly frames the compressed data,
    // so LZMA does not need a known uncompressed size.
    let method = detect_compression(compressed_data);
    if let Ok(decompressed) = decompress_block(compressed_data, method, expected_size, None) {
        if !decompressed.is_empty() {
            return Ok((
                decompressed,
                method,
                CompressionMode::NonSolid,
                non_solid_consumed,
            ));
        }
    }

    // If the detected method failed, try the other methods.
    let methods = [
        CompressionMethod::Lzma,
        CompressionMethod::Deflate,
        CompressionMethod::Bzip2,
    ];
    for &m in &methods {
        if m == method {
            continue;
        }
        if let Ok(decompressed) = decompress_block(compressed_data, m, expected_size, None) {
            if !decompressed.is_empty() {
                return Ok((
                    decompressed,
                    m,
                    CompressionMode::NonSolid,
                    non_solid_consumed,
                ));
            }
        }
    }

    // Non-solid decompression failed entirely.
    // Try solid mode: the entire post-FirstHeader data is one compressed stream.
    // For solid LZMA, trailing data (data block, CRC) follows the header's EOS
    // marker, so we must provide the exact expected size to avoid lzma-rs
    // rejecting the stream for having trailing bytes.
    //
    // In solid mode the decompressed stream is framed: each sub-block starts
    // with a 4-byte LE length prefix. The NSIS loader (`_dodecomp` in
    // `fileform.c`) reads and consumes this prefix before returning the header
    // data. We must include those 4 bytes in the decompression output and
    // strip them afterwards.
    let solid_expected = expected_size + 4; // account for in-stream length prefix
    let solid_method = detect_compression(data);
    if let Ok(decompressed) =
        decompress_block(data, solid_method, solid_expected, Some(solid_expected))
    {
        let stripped = strip_solid_prefix(decompressed)?;
        // Solid: the entire stream is one blob, no separate data block offset.
        return Ok((stripped, solid_method, CompressionMode::Solid, 0));
    }

    for &m in &methods {
        if m == solid_method {
            continue;
        }
        if let Ok(decompressed) = decompress_block(data, m, solid_expected, Some(solid_expected)) {
            let stripped = strip_solid_prefix(decompressed)?;
            return Ok((stripped, m, CompressionMode::Solid, 0));
        }
    }

    Err(Error::UnsupportedCompression)
}

/// Strips the 4-byte in-stream length prefix from solid-mode decompressed data.
///
/// In solid mode, the NSIS decompressed stream starts with a 4-byte LE integer
/// containing the size of the following header data. The NSIS runtime loader
/// (`_dodecomp` in `fileform.c`) reads and discards this prefix. We do the same.
///
/// Validates that the prefix value matches the remaining data length.
fn strip_solid_prefix(data: Vec<u8>) -> Result<Vec<u8>, Error> {
    if data.len() < 4 {
        return Err(Error::TooShort {
            expected: 4,
            actual: data.len(),
            context: "solid stream length prefix",
        });
    }
    let prefix = crate::util::read_u32_le(&data, 0) as usize;
    if prefix == data.len() - 4 {
        // Prefix matches exactly — strip it.
        Ok(data[4..].to_vec())
    } else {
        // Prefix doesn't match. This can happen if the data isn't actually
        // solid-framed (e.g., some NSIS versions omit the prefix). Return
        // the data as-is and let the caller validate.
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_length_prefix_compressed() {
        // bit 31 set, lower 31 bits = 1000
        let val = 0x8000_0000u32 | 1000;
        let data = val.to_le_bytes();
        let (is_compressed, size) = read_length_prefix(&data).unwrap();
        assert!(is_compressed);
        assert_eq!(size, 1000);
    }

    #[test]
    fn read_length_prefix_uncompressed() {
        let val = 2048u32;
        let data = val.to_le_bytes();
        let (is_compressed, size) = read_length_prefix(&data).unwrap();
        assert!(!is_compressed);
        assert_eq!(size, 2048);
    }

    #[test]
    fn read_length_prefix_too_short() {
        let data = [0u8; 3];
        assert!(read_length_prefix(&data).is_err());
    }

    #[test]
    fn detect_compression_lzma() {
        let data = [0x5D, 0x00, 0x00, 0x01, 0x00, 0xFF];
        assert_eq!(detect_compression(&data), CompressionMethod::Lzma);
    }

    #[test]
    fn detect_compression_bzip2() {
        let data = [0x31, 0x41, 0x59, 0x26];
        assert_eq!(detect_compression(&data), CompressionMethod::Bzip2);
    }

    #[test]
    fn detect_compression_deflate_fallback() {
        let data = [0x78, 0x9C, 0x01, 0x02];
        assert_eq!(detect_compression(&data), CompressionMethod::Deflate);
    }

    #[test]
    fn detect_compression_empty() {
        assert_eq!(detect_compression(&[]), CompressionMethod::None);
    }

    #[test]
    fn decompress_header_uncompressed() {
        let payload = b"hello world test data";
        let size = payload.len() as u32;
        let mut data = Vec::new();
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(payload);
        let (decompressed, method, mode, consumed) =
            decompress_header(&data, payload.len()).unwrap();
        assert_eq!(&decompressed, payload);
        assert_eq!(method, CompressionMethod::None);
        assert_eq!(mode, CompressionMode::NonSolid);
        assert_eq!(consumed, 4 + payload.len());
    }
}
