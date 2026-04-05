//! NSIS opcode definitions and version-aware resolution.
//!
//! NSIS uses approximately 71 opcodes (`EW_INVALID_OPCODE` through `EW_FGETWS`),
//! but the exact numbering shifts between NSIS versions due to conditional
//! compilation with `#ifdef`. This module provides:
//!
//! - [`OpcodeInfo`]: Static metadata for each opcode.
//! - [`NsisVersion`]: Version enum for version-aware opcode resolution.
//! - [`lookup`]: Resolves an opcode index to its info for a given version.
//!
//! Source: `fileform.h` and `exec.c` from the NSIS source code.

pub mod info;
pub mod version;

pub use info::OpcodeInfo;
pub use version::NsisVersion;

// Opcode indices from `fileform.h`.
// These are the `which` values stored in entry structures.

/// Invalid/error opcode.
pub const EW_INVALID_OPCODE: i32 = 0;
/// Return from function.
pub const EW_RET: i32 = 1;
/// No-op / jump.
pub const EW_NOP: i32 = 2;
/// Abort installation.
pub const EW_ABORT: i32 = 3;
/// Quit installer.
pub const EW_QUIT: i32 = 4;
/// Call subroutine.
pub const EW_CALL: i32 = 5;
/// Update status text.
pub const EW_UPDATETEXT: i32 = 6;
/// Sleep.
pub const EW_SLEEP: i32 = 7;
/// Bring window to front.
pub const EW_BRINGTOFRONT: i32 = 8;
/// Set details view.
pub const EW_CHDETAILSVIEW: i32 = 9;
/// Set file attributes.
pub const EW_SETFILEATTRIBUTES: i32 = 10;
/// Create directory.
pub const EW_CREATEDIR: i32 = 11;
/// If file exists.
pub const EW_IFFILEEXISTS: i32 = 12;
/// Set exec flag.
pub const EW_SETFLAG: i32 = 13;
/// If flag set.
pub const EW_IFFLAG: i32 = 14;
/// Get exec flag.
pub const EW_GETFLAG: i32 = 15;
/// Rename/move file.
pub const EW_RENAME: i32 = 16;
/// Get full path name.
pub const EW_GETFULLPATHNAME: i32 = 17;
/// Search PATH.
pub const EW_SEARCHPATH: i32 = 18;
/// Get temp filename.
pub const EW_GETTEMPFILENAME: i32 = 19;
/// Extract file from archive.
pub const EW_EXTRACTFILE: i32 = 20;
/// Delete file.
pub const EW_DELETEFILE: i32 = 21;
/// Message box.
pub const EW_MESSAGEBOX: i32 = 22;
/// Remove directory.
pub const EW_RMDIR: i32 = 23;
/// String length.
pub const EW_STRLEN: i32 = 24;
/// StrCpy.
pub const EW_ASSIGNVAR: i32 = 25;
/// String compare.
pub const EW_STRCMP: i32 = 26;
/// ReadEnvStr / ExpandEnvStrings.
pub const EW_READENVSTR: i32 = 27;
/// Integer compare.
pub const EW_INTCMP: i32 = 28;
/// Integer operation.
pub const EW_INTOP: i32 = 29;
/// IntFmt / Int64Fmt.
pub const EW_INTFMT: i32 = 30;
/// Push / Pop / Exch.
pub const EW_PUSHPOP: i32 = 31;
/// FindWindow.
pub const EW_FINDWINDOW: i32 = 32;
/// SendMessage.
pub const EW_SENDMESSAGE: i32 = 33;
/// IsWindow.
pub const EW_ISWINDOW: i32 = 34;
/// GetDlgItem.
pub const EW_GETDLGITEM: i32 = 35;
/// Set control colors.
pub const EW_SETCTLCOLORS: i32 = 36;
/// Load and set image.
pub const EW_LOADANDSETIMAGE: i32 = 37;
/// CreateFont.
pub const EW_CREATEFONT: i32 = 38;
/// ShowWindow.
pub const EW_SHOWWINDOW: i32 = 39;
/// ShellExecute.
pub const EW_SHELLEXEC: i32 = 40;
/// Exec / ExecWait.
pub const EW_EXECUTE: i32 = 41;
/// GetFileTime.
pub const EW_GETFILETIME: i32 = 42;
/// GetDLLVersion.
pub const EW_GETDLLVERSION: i32 = 43;
/// RegisterDLL / plugin call.
pub const EW_REGISTERDLL: i32 = 44;
/// CreateShortcut.
pub const EW_CREATESHORTCUT: i32 = 45;
/// CopyFiles.
pub const EW_COPYFILES: i32 = 46;
/// Reboot.
pub const EW_REBOOT: i32 = 47;
/// WriteINIStr.
pub const EW_WRITEINI: i32 = 48;
/// ReadINIStr.
pub const EW_READINISTR: i32 = 49;
/// DeleteRegValue / Key.
pub const EW_DELREG: i32 = 50;
/// WriteRegStr / DWORD / Bin.
pub const EW_WRITEREG: i32 = 51;
/// ReadRegStr / DWORD.
pub const EW_READREGSTR: i32 = 52;
/// RegEnumKey / Value.
pub const EW_REGENUM: i32 = 53;
/// FileClose.
pub const EW_FCLOSE: i32 = 54;
/// FileOpen.
pub const EW_FOPEN: i32 = 55;
/// FileWrite.
pub const EW_FPUTS: i32 = 56;
/// FileRead.
pub const EW_FGETS: i32 = 57;
/// FileSeek.
pub const EW_FSEEK: i32 = 58;
/// FindClose.
pub const EW_FINDCLOSE: i32 = 59;
/// FindNext.
pub const EW_FINDNEXT: i32 = 60;
/// FindFirst.
pub const EW_FINDFIRST: i32 = 61;
/// WriteUninstaller.
pub const EW_WRITEUNINSTALLER: i32 = 62;
/// LogText / LogSet.
pub const EW_LOG: i32 = 63;
/// SectionSet / GetText / Flags.
pub const EW_SECTIONSET: i32 = 64;
/// InstTypeSet / GetFlags.
pub const EW_INSTTYPESET: i32 = 65;
/// GetOSInfo / GetKnownFolderPath.
pub const EW_GETOSINFO: i32 = 66;
/// Reserved / free slot.
pub const EW_RESERVEDOPCODE: i32 = 67;
/// Lock / unlock window updates.
pub const EW_LOCKWINDOW: i32 = 68;
/// FileWriteUTF16LE.
pub const EW_FPUTWS: i32 = 69;
/// FileReadUTF16LE.
pub const EW_FGETWS: i32 = 70;

/// Looks up opcode metadata for the given opcode index and NSIS version.
///
/// Returns `None` if the opcode index is out of range for the given version.
pub fn lookup(version: NsisVersion, which: u32) -> Option<&'static OpcodeInfo> {
    let table: &[OpcodeInfo] = match version {
        NsisVersion::V2 => &info::OPCODES_NSIS2,
        NsisVersion::V3 => info::OPCODES_NSIS3,
        // V1 and Park use the V2 table as a fallback.
        NsisVersion::V1 | NsisVersion::Park => &info::OPCODES_NSIS2,
    };

    table.get(which as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_valid_opcode() {
        let info = lookup(NsisVersion::V2, 0);
        assert!(info.is_some());
        assert_eq!(info.unwrap().mnemonic, "EW_INVALID_OPCODE");
    }

    #[test]
    fn lookup_ret() {
        let info = lookup(NsisVersion::V2, 1).unwrap();
        assert_eq!(info.mnemonic, "EW_RET");
    }

    #[test]
    fn lookup_out_of_range() {
        assert!(lookup(NsisVersion::V2, 999).is_none());
    }

    #[test]
    fn lookup_v3() {
        let info = lookup(NsisVersion::V3, 0).unwrap();
        assert_eq!(info.mnemonic, "EW_INVALID_OPCODE");
    }
}
