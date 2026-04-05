//! NSIS version detection.
//!
//! Since the common header layout and opcode numbering vary between NSIS
//! versions, parsers must detect the version heuristically.
//!
//! Source: NRS `nsisfile.py` `_detect_version()` and Binary Refinery `xtnsis.py`.

use crate::strings::StringEncoding;

/// Identifies the NSIS version for opcode resolution and header layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsisVersion {
    /// NSIS 1.x (legacy `"nsisinstall"` signature).
    V1,
    /// NSIS 2.x (ANSI strings, ~67 opcodes).
    V2,
    /// NSIS 3.x (Unicode strings, ~71 opcodes).
    V3,
    /// Jim Park's Unicode fork.
    Park,
}

impl NsisVersion {
    /// Detects the NSIS version from available heuristics.
    ///
    /// # Heuristics (from RESEARCH.md section 12)
    ///
    /// 1. String encoding: Unicode → NSIS 3.x; Park → Park; ANSI → NSIS 2.x
    /// 2. Max opcode: v2 has ~67, v3 has ~71
    /// 3. Legacy signature → NSIS 1.x
    pub fn detect(encoding: StringEncoding, is_legacy_signature: bool) -> Self {
        if is_legacy_signature {
            return NsisVersion::V1;
        }

        match encoding {
            StringEncoding::Unicode => NsisVersion::V3,
            StringEncoding::Park => NsisVersion::Park,
            StringEncoding::Ansi => NsisVersion::V2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_v1_from_legacy() {
        assert_eq!(
            NsisVersion::detect(StringEncoding::Ansi, true),
            NsisVersion::V1
        );
    }

    #[test]
    fn detect_v2_from_ansi() {
        assert_eq!(
            NsisVersion::detect(StringEncoding::Ansi, false),
            NsisVersion::V2
        );
    }

    #[test]
    fn detect_v3_from_unicode() {
        assert_eq!(
            NsisVersion::detect(StringEncoding::Unicode, false),
            NsisVersion::V3
        );
    }

    #[test]
    fn detect_park() {
        assert_eq!(
            NsisVersion::detect(StringEncoding::Park, false),
            NsisVersion::Park
        );
    }
}
