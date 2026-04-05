//! NSIS header structures.
//!
//! This module contains parsers for the three header layers:
//!
//! - [`FirstHeader`]: The 28-byte signature and size block found in the PE overlay.
//! - [`BlockHeader`]: An 8-byte descriptor (offset + count) for each data block.
//! - [`CommonHeader`]: The main header containing flags, block descriptors, callbacks,
//!   and install configuration.
//!
//! # Structure Chain
//!
//! ```text
//! PE Overlay
//! └─ FirstHeader (28 bytes, at 512-byte aligned offset)
//!    └─ Compressed Header Block
//!       └─ CommonHeader
//!          ├─ BlockHeader[0] → Pages
//!          ├─ BlockHeader[1] → Sections
//!          ├─ BlockHeader[2] → Entries
//!          ├─ BlockHeader[3] → Strings
//!          ├─ BlockHeader[4] → LangTables
//!          ├─ BlockHeader[5] → CtlColors
//!          ├─ BlockHeader[6] → BgFont
//!          └─ BlockHeader[7] → Data
//! ```

pub mod blockheader;
pub mod commonheader;
pub mod firstheader;

pub use blockheader::{BLOCKS_NUM, BlockHeader, BlockType};
pub use commonheader::CommonHeader;
pub use firstheader::FirstHeader;

use crate::error::Error;

/// Hint about which NSIS version produced an installer.
///
/// This is determined heuristically from header structure sizes,
/// string encoding, and opcode ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsisVersionHint {
    /// NSIS 1.x (legacy `"nsisinstall"` signature).
    Nsis1x,
    /// NSIS 2.x (ANSI strings, ~67 opcodes).
    Nsis2x,
    /// NSIS 3.x (Unicode strings, ~71 opcodes).
    Nsis3x,
    /// Jim Park's Unicode fork (hybrid encoding).
    Park,
    /// Version could not be determined.
    Unknown,
}

/// Scans the overlay for a valid NSIS FirstHeader at 512-byte aligned offsets.
///
/// Returns the byte offset within the overlay and the parsed [`FirstHeader`].
///
/// Per the NSIS forums: "All IDPOS values for the ID 'NullsoftInst' can be
/// calculated using the formula in hex format: `O=8+512*n`." The 7-zip NSIS
/// handler searches at 512-byte steps after the PE stub.
///
/// # Errors
///
/// Returns [`Error::SignatureNotFound`] if no valid signature is found.
pub fn scan_for_first_header(overlay: &[u8]) -> Result<(usize, FirstHeader<'_>), Error> {
    // Scan at 512-byte aligned offsets, starting from offset 0.
    let mut offset = 0;
    while offset + FirstHeader::SIZE <= overlay.len() {
        if let Ok(fh) = FirstHeader::parse(&overlay[offset..]) {
            return Ok((offset, fh));
        }
        offset += 512;
    }
    Err(Error::SignatureNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: builds a valid FirstHeader byte buffer.
    fn make_first_header(flags: u32) -> [u8; 28] {
        let mut buf = [0u8; 28];
        buf[0..4].copy_from_slice(&flags.to_le_bytes());
        buf[4..8].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        buf[8..12].copy_from_slice(&0x6C6C754Eu32.to_le_bytes()); // "Null"
        buf[12..16].copy_from_slice(&0x74666F73u32.to_le_bytes()); // "soft"
        buf[16..20].copy_from_slice(&0x74736E49u32.to_le_bytes()); // "Inst"
        buf[20..24].copy_from_slice(&1024i32.to_le_bytes()); // length_of_header
        buf[24..28].copy_from_slice(&2048i32.to_le_bytes()); // length_of_all
        buf
    }

    #[test]
    fn scan_finds_header_at_offset_zero() {
        let fh = make_first_header(0);
        let mut overlay = vec![0u8; 1024];
        overlay[..28].copy_from_slice(&fh);

        let (off, _hdr) = scan_for_first_header(&overlay).unwrap();
        assert_eq!(off, 0);
    }

    #[test]
    fn scan_finds_header_at_512() {
        let fh = make_first_header(0);
        let mut overlay = vec![0u8; 2048];
        overlay[512..512 + 28].copy_from_slice(&fh);

        let (off, _hdr) = scan_for_first_header(&overlay).unwrap();
        assert_eq!(off, 512);
    }

    #[test]
    fn scan_finds_header_at_1024() {
        let fh = make_first_header(0x01); // uninstaller flag
        let mut overlay = vec![0u8; 2048];
        overlay[1024..1024 + 28].copy_from_slice(&fh);

        let (off, hdr) = scan_for_first_header(&overlay).unwrap();
        assert_eq!(off, 1024);
        assert!(hdr.is_uninstaller());
    }

    #[test]
    fn scan_fails_on_empty_overlay() {
        let overlay = vec![0u8; 512];
        assert_eq!(
            scan_for_first_header(&overlay),
            Err(Error::SignatureNotFound)
        );
    }

    #[test]
    fn scan_fails_on_non_aligned_header() {
        let fh = make_first_header(0);
        let mut overlay = vec![0u8; 2048];
        // Place header at non-aligned offset 256 — should not be found.
        overlay[256..256 + 28].copy_from_slice(&fh);

        assert_eq!(
            scan_for_first_header(&overlay),
            Err(Error::SignatureNotFound)
        );
    }
}
