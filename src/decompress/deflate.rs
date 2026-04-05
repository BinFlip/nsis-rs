//! Raw deflate decompression for NSIS data blocks.
//!
//! NSIS uses raw deflate (no zlib header) for its default compression.

use crate::error::Error;

/// Decompresses raw deflate data.
///
/// NSIS uses raw deflate (RFC 1951) without zlib or gzip framing.
///
/// # Arguments
///
/// - `compressed`: the raw deflate stream
/// - `max_output`: maximum decompressed size (prevents memory exhaustion)
///
/// # Errors
///
/// Returns [`Error::DecompressionFailed`] if the deflate stream is invalid.
pub fn decompress_deflate(compressed: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let mut decompressor = flate2::Decompress::new(false); // raw deflate, no zlib header
    let mut output = vec![0u8; max_output];

    let status = decompressor
        .decompress(compressed, &mut output, flate2::FlushDecompress::Finish)
        .map_err(|e| Error::DecompressionFailed {
            method: "deflate",
            detail: e.to_string(),
        })?;

    let bytes_written = decompressor.total_out() as usize;

    match status {
        flate2::Status::Ok | flate2::Status::StreamEnd => {
            output.truncate(bytes_written);
            Ok(output)
        }
        flate2::Status::BufError => {
            // Output buffer was too small — return what we have.
            output.truncate(bytes_written);
            Ok(output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compress;

    #[test]
    fn roundtrip_deflate() {
        let original = b"Hello, NSIS installer world! This is test data for deflate.";
        let mut compressed = vec![0u8; original.len() + 64];
        let mut compressor = Compress::new(flate2::Compression::default(), false);
        let status = compressor
            .compress(original, &mut compressed, flate2::FlushCompress::Finish)
            .unwrap();
        assert_eq!(status, flate2::Status::StreamEnd);
        let compressed_len = compressor.total_out() as usize;
        compressed.truncate(compressed_len);

        let decompressed = decompress_deflate(&compressed, original.len()).unwrap();
        assert_eq!(&decompressed, original);
    }

    #[test]
    fn invalid_deflate_data() {
        let garbage = [0xFF, 0xFE, 0xFD, 0xFC];
        let result = decompress_deflate(&garbage, 1024);
        assert!(result.is_err());
    }
}
