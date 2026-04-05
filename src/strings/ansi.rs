//! ANSI string decoding for NSIS.
//!
//! In ANSI mode, strings are single-byte characters with embedded special
//! codes followed by 2 coded bytes containing a 14-bit value.
//!
//! Two code ranges exist depending on the NSIS version:
//!
//! | Version | SKIP | VAR | SHELL | LANG |
//! |---------|------|-----|-------|------|
//! | NSIS 3.x | 0x04 | 0x03 | 0x02 | 0x01 |
//! | NSIS 2.x | 0xFC (252) | 0xFD (253) | 0xFE (254) | 0xFF (255) |
//!
//! This reader handles both ranges transparently.
//!
//! Sources: `fileform.h`, NRS `nsis2.py` / `nsis3.py`.

use crate::{
    error::Error,
    strings::{NsisString, StringSegment, decode_short},
};

/// NSIS 3.x ANSI special codes.
const NS3_LANG: u8 = 0x01;
const NS3_SHELL: u8 = 0x02;
const NS3_VAR: u8 = 0x03;
const NS3_SKIP: u8 = 0x04;

/// NSIS 2.x ANSI special codes.
const NS2_SKIP: u8 = 0xFC;
const NS2_VAR: u8 = 0xFD;
const NS2_SHELL: u8 = 0xFE;
const NS2_LANG: u8 = 0xFF;

/// Classifies a byte as an NSIS special code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnsiCode {
    Literal,
    Skip,
    Var,
    Shell,
    Lang,
}

fn classify_byte(b: u8) -> AnsiCode {
    match b {
        NS3_LANG | NS2_LANG => AnsiCode::Lang,
        NS3_SHELL | NS2_SHELL => AnsiCode::Shell,
        NS3_VAR | NS2_VAR => AnsiCode::Var,
        NS3_SKIP | NS2_SKIP => AnsiCode::Skip,
        _ => AnsiCode::Literal,
    }
}

/// Reads an ANSI-encoded NSIS string from the string table.
///
/// Handles both NSIS 2.x (`0xFC-0xFF`) and NSIS 3.x (`0x01-0x04`) special codes.
/// The string starts at `offset` and continues until a null byte (`0x00`).
pub fn read_ansi_string(table: &[u8], offset: usize) -> Result<NsisString, Error> {
    let mut segments = Vec::new();
    let mut literal = String::new();
    let mut pos = offset;

    while pos < table.len() {
        let b = table[pos];

        if b == 0 {
            break;
        }

        let code = classify_byte(b);

        if code != AnsiCode::Literal {
            if code == AnsiCode::Skip {
                // Next byte is a literal character (no flush needed).
                pos += 1;
                if pos < table.len() {
                    literal.push(table[pos] as char);
                }
                pos += 1;
                continue;
            }

            // Flush accumulated literal before emitting a special segment.
            if !literal.is_empty() {
                segments.push(StringSegment::Literal(literal.clone()));
                literal.clear();
            }

            // Read the 2-byte coded short.
            if pos + 2 >= table.len() {
                break;
            }
            let val = decode_short(table[pos + 1], table[pos + 2]);
            pos += 3;

            match code {
                AnsiCode::Var => segments.push(StringSegment::Variable(val)),
                AnsiCode::Shell => segments.push(StringSegment::ShellFolder(val)),
                AnsiCode::Lang => segments.push(StringSegment::LangString(val)),
                _ => {}
            }
        } else {
            literal.push(b as char);
            pos += 1;
        }
    }

    if !literal.is_empty() {
        segments.push(StringSegment::Literal(literal));
    }

    Ok(NsisString { segments })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strings::encode_short;

    #[test]
    fn plain_string() {
        let table = b"Hello World\0rest";
        let s = read_ansi_string(table, 0).unwrap();
        assert_eq!(s.segments.len(), 1);
        assert_eq!(s.segments[0], StringSegment::Literal("Hello World".into()));
    }

    #[test]
    fn nsis3_variable() {
        // NSIS 3.x: NS_VAR_CODE = 0x03
        let (b0, b1) = encode_short(21);
        let mut table = Vec::new();
        table.extend_from_slice(b"Install to ");
        table.push(NS3_VAR);
        table.push(b0);
        table.push(b1);
        table.push(0);

        let s = read_ansi_string(&table, 0).unwrap();
        assert_eq!(s.segments.len(), 2);
        assert_eq!(s.segments[0], StringSegment::Literal("Install to ".into()));
        assert_eq!(s.segments[1], StringSegment::Variable(21));
        assert_eq!(s.to_string(), "Install to $INSTDIR");
    }

    #[test]
    fn nsis2_variable() {
        // NSIS 2.x: NS_VAR_CODE = 0xFD
        let (b0, b1) = encode_short(21);
        let mut table = Vec::new();
        table.extend_from_slice(b"Dir: ");
        table.push(NS2_VAR);
        table.push(b0);
        table.push(b1);
        table.push(0);

        let s = read_ansi_string(&table, 0).unwrap();
        assert_eq!(s.segments.len(), 2);
        assert_eq!(s.segments[0], StringSegment::Literal("Dir: ".into()));
        assert_eq!(s.segments[1], StringSegment::Variable(21));
    }

    #[test]
    fn nsis2_shell_folder() {
        let (b0, b1) = encode_short(0x001A); // CSIDL_APPDATA
        let mut table = Vec::new();
        table.push(NS2_SHELL);
        table.push(b0);
        table.push(b1);
        table.extend_from_slice(b"\\MyApp\0");

        let s = read_ansi_string(&table, 0).unwrap();
        assert_eq!(s.segments.len(), 2);
        assert_eq!(s.segments[0], StringSegment::ShellFolder(0x001A));
        assert_eq!(s.segments[1], StringSegment::Literal("\\MyApp".into()));
    }

    #[test]
    fn nsis3_skip_code() {
        let mut table = Vec::new();
        table.extend_from_slice(b"A");
        table.push(NS3_SKIP);
        table.push(0x03); // literal 0x03
        table.extend_from_slice(b"B\0");

        let s = read_ansi_string(&table, 0).unwrap();
        assert_eq!(s.segments.len(), 1);
        assert_eq!(s.segments[0], StringSegment::Literal("A\x03B".into()));
    }

    #[test]
    fn nsis2_skip_code() {
        let table = vec![NS2_SKIP, NS2_VAR, 0]; // SKIP makes 0xFD literal

        let s = read_ansi_string(&table, 0).unwrap();
        assert_eq!(s.segments.len(), 1);
        assert_eq!(
            s.segments[0],
            StringSegment::Literal(String::from(NS2_VAR as char))
        );
    }

    #[test]
    fn string_at_offset() {
        let table = b"\0\0\0Hello\0";
        let s = read_ansi_string(table, 3).unwrap();
        assert_eq!(s.segments.len(), 1);
        assert_eq!(s.segments[0], StringSegment::Literal("Hello".into()));
    }

    #[test]
    fn empty_string() {
        let table = b"\0";
        let s = read_ansi_string(table, 0).unwrap();
        assert!(s.is_empty());
    }
}
