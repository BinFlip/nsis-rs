//! The main NSIS installer parser entry point.

use crate::{
    addressmap::PeOverlay,
    decompress::{self, CompressionMethod, CompressionMode},
    error::Error,
    header::{
        self, NsisVersionHint, blockheader::BlockType, commonheader::CommonHeader,
        firstheader::FirstHeader,
    },
    installer::{
        analysis::{ExecIter, PluginCallIter, RegistryIter, ShortcutIter, UninstallerIter},
        files::FileIter,
    },
    nsis::{
        entry::{Entry, EntryIter},
        langtable::LangTableIter,
        page::PageIter,
        section::{Section, SectionIter},
    },
    opcode::{self, NsisVersion, ParkSubVersion},
    strings::{self, NsisString, StringEncoding},
};

/// Parsed NSIS installer providing access to all internal structures.
///
/// The installer borrows the original file bytes (`'a` lifetime) and owns
/// the decompressed header data. All view types returned by accessor methods
/// borrow from one of these two buffers.
///
/// # Example
///
/// ```no_run
/// use nsis::NsisInstaller;
///
/// let file = std::fs::read("installer.exe").unwrap();
/// let inst = NsisInstaller::from_bytes(&file).unwrap();
///
/// println!("Version: {:?}", inst.version());
/// println!("Sections: {}", inst.section_count());
/// for section in inst.sections() {
///     let section = section.unwrap();
///     println!("  code_size={}", section.code_size());
/// }
/// ```
pub struct NsisInstaller<'a> {
    /// The original file bytes (borrowed).
    file: &'a [u8],
    /// Byte offset of the FirstHeader within the file.
    first_header_file_offset: usize,
    /// Decompressed header data (owned).
    header_data: Vec<u8>,
    /// Detected compression method.
    compression: CompressionMethod,
    /// Detected compression mode.
    mode: CompressionMode,
    /// Detected NSIS version.
    version: NsisVersion,
    /// Detected string encoding.
    encoding: StringEncoding,
    /// FirstHeader flags (cached).
    first_header_flags: u32,
    /// Whether the FirstHeader uses a legacy signature.
    is_legacy: bool,
    /// Byte offset of the data block within the original file (non-solid only).
    data_block_offset: usize,
    /// Decompressed solid file data (solid mode only).
    ///
    /// In solid mode, this contains the decompressed file data stream
    /// (everything after the header in the solid decompressed stream).
    /// Each file entry is framed with a 4-byte length prefix.
    /// `EW_EXTRACTFILE` `data_offset` values are byte positions into this buffer.
    solid_data: Vec<u8>,
    /// Parsed block offsets and counts: (offset_in_header, item_count).
    blocks: [(u32, i32); 8],
    /// Common header flags.
    common_flags: u32,
    /// Language table entry size.
    langtable_size: i32,
    /// On-disk section size (base 24 bytes + optional inline name buffer).
    section_size: usize,
    /// Callback entry indices from the common header.
    ///
    /// Order: onInit, onInstSuccess, onInstFailed, onUserAbort, onGUIInit,
    /// onGUIEnd, onMouseOverSection, onVerifyInstDir, onSelChange, onRebootFailed.
    /// Value of -1 means the callback is not defined.
    callbacks: [i32; 10],
    /// Park sub-version (only meaningful when `version == Park`).
    park_sub: Option<ParkSubVersion>,
}

impl<'a> NsisInstaller<'a> {
    /// Parses an NSIS installer from the given file bytes.
    ///
    /// This performs the full parsing pipeline:
    /// 1. Locate PE overlay
    /// 2. Scan for FirstHeader at 512-byte aligned offsets
    /// 3. Decompress the header block
    /// 4. Parse the common header and block descriptors
    /// 5. Detect string encoding and NSIS version
    ///
    /// # Errors
    ///
    /// Returns an error if any step fails (not a PE, no overlay, no NSIS
    /// signature, decompression failure, invalid headers).
    pub fn from_bytes(file: &'a [u8]) -> Result<Self, Error> {
        // Step 1: Locate the PE overlay.
        let overlay_info = PeOverlay::from_bytes(file)?;
        let overlay = overlay_info.overlay();
        let overlay_file_offset = overlay_info.overlay_offset();

        // Step 2: Scan for the FirstHeader.
        let (fh_overlay_offset, first_header) = header::scan_for_first_header(overlay)?;
        let first_header_file_offset = overlay_file_offset + fh_overlay_offset;
        let is_legacy = first_header.is_legacy();

        // Data after the FirstHeader.
        let after_fh_start = fh_overlay_offset + FirstHeader::SIZE;
        if after_fh_start >= overlay.len() {
            return Err(Error::TooShort {
                expected: after_fh_start + 1,
                actual: overlay.len(),
                context: "data after FirstHeader",
            });
        }
        let after_fh = &overlay[after_fh_start..];

        // Step 3: Decompress the header block.
        let expected_size = first_header.length_of_header() as usize;
        let (header_data, compression, mode, header_compressed_size) =
            decompress::decompress_header(after_fh, expected_size)?;

        // Step 4: Parse the common header and extract all values before
        // moving header_data into the struct (CommonHeader borrows header_data).
        let (blocks, common_flags, langtable_size, callbacks) = {
            let common_header = CommonHeader::parse(&header_data, NsisVersionHint::Unknown)?;
            let mut blocks = [(0u32, 0i32); 8];
            for (i, block) in blocks.iter_mut().enumerate() {
                let bh = &common_header.blocks()[i];
                *block = (bh.offset(), bh.num());
            }
            let callbacks = [
                common_header.code_on_init(),
                common_header.code_on_inst_success(),
                common_header.code_on_inst_failed(),
                common_header.code_on_user_abort(),
                common_header.code_on_gui_init(),
                common_header.code_on_gui_end(),
                common_header.code_on_mouse_over_section(),
                common_header.code_on_verify_inst_dir(),
                common_header.code_on_sel_change(),
                common_header.code_on_reboot_failed(),
            ];
            (
                blocks,
                common_header.flags(),
                common_header.langtable_size(),
                callbacks,
            )
        };

        // Compute section size from block header gaps (7-Zip NsisIn.cpp line 5260).
        let sec_offset = blocks[BlockType::Sections as usize].0 as usize;
        let sec_count = blocks[BlockType::Sections as usize].1.max(0) as usize;
        let ent_offset = blocks[BlockType::Entries as usize].0 as usize;
        let section_size = if sec_count > 0 && ent_offset > sec_offset {
            (ent_offset - sec_offset) / sec_count
        } else {
            Section::BASE_SIZE
        };

        // Step 5: Detect string encoding and version.
        let string_block_offset = blocks[BlockType::Strings as usize].0 as usize;
        let encoding = if string_block_offset < header_data.len() {
            strings::detect_encoding(&header_data[string_block_offset..])
        } else {
            StringEncoding::Ansi
        };

        let version = NsisVersion::detect(encoding, is_legacy);

        // Step 5b: Detect Park sub-version by scanning entries.
        let park_sub = if version == NsisVersion::Park {
            let ent_offset = blocks[BlockType::Entries as usize].0 as usize;
            let ent_count = blocks[BlockType::Entries as usize].1.max(0) as usize;
            Some(opcode::detect_park_sub_version(
                &header_data,
                ent_offset,
                ent_count,
            ))
        } else {
            None
        };

        // Step 6: Handle data block.
        let (data_block_offset, solid_data) = if mode == CompressionMode::Solid {
            // In solid mode, the entire post-FirstHeader data is one compressed
            // stream. Decompress the full stream to get the file data.
            //
            // Decompressed stream: [4B header_len][header][4B file1_len][file1]...
            //
            // The NSIS overlay may be followed by extra data (digital signatures,
            // padding) beyond what `length_of_all_following_data` covers. Also,
            // the last 4 bytes within the NSIS data may be a CRC32 that is NOT
            // part of the compressed stream. Trim to the exact NSIS data bounds
            // and exclude the CRC to avoid LZMA "trailing bytes" errors.
            let nsis_data_len = (first_header.length_of_all_following_data() as usize)
                .saturating_sub(FirstHeader::SIZE);
            let has_crc = !first_header.has_no_crc();
            let stream_len = if has_crc {
                nsis_data_len.saturating_sub(4)
            } else {
                nsis_data_len
            };
            let compressed_data = &after_fh[..stream_len.min(after_fh.len())];

            let max_decompressed = nsis_data_len.max(expected_size * 10).max(64 * 1024 * 1024);

            // Decompress the full stream. If this fails, file extraction won't
            // work but header parsing still succeeds — we degrade gracefully.
            let full_stream =
                decompress::decompress_block(compressed_data, compression, max_decompressed, None)
                    .unwrap_or_else(|_| Vec::new());

            // The first 4 bytes are the header length prefix, then header_data.
            // File data starts after: 4 + header_data.len()
            let file_data_start = 4 + header_data.len();
            let solid_file_data = if file_data_start < full_stream.len() {
                full_stream[file_data_start..].to_vec()
            } else {
                Vec::new()
            };

            (0, solid_file_data)
        } else {
            // In non-solid mode, the data block follows the compressed header.
            // `header_compressed_size` already includes the 4-byte length prefix.
            let offset = first_header_file_offset + FirstHeader::SIZE + header_compressed_size;
            (offset, Vec::new())
        };

        Ok(Self {
            file,
            first_header_file_offset,
            header_data,
            compression,
            mode,
            version,
            encoding,
            first_header_flags: first_header.flags(),
            is_legacy,
            data_block_offset,
            solid_data,
            blocks,
            common_flags,
            langtable_size,
            section_size,
            callbacks,
            park_sub,
        })
    }

    /// Returns the detected NSIS version.
    #[inline]
    pub fn version(&self) -> NsisVersion {
        self.version
    }

    /// Returns the detected compression method.
    #[inline]
    pub fn compression(&self) -> CompressionMethod {
        self.compression
    }

    /// Returns the detected compression mode (solid or non-solid).
    #[inline]
    pub fn compression_mode(&self) -> CompressionMode {
        self.mode
    }

    /// Returns the detected string encoding.
    #[inline]
    pub fn string_encoding(&self) -> StringEncoding {
        self.encoding
    }

    /// Returns `true` if this is an uninstaller.
    #[inline]
    pub fn is_uninstaller(&self) -> bool {
        self.first_header_flags & crate::header::firstheader::FH_FLAGS_UNINSTALL != 0
    }

    /// Returns `true` if this is a legacy NSIS 1.x installer.
    #[inline]
    pub fn is_legacy(&self) -> bool {
        self.is_legacy
    }

    /// Returns the byte offset of the FirstHeader in the file.
    #[inline]
    pub fn first_header_file_offset(&self) -> usize {
        self.first_header_file_offset
    }

    /// Returns the common header flags.
    #[inline]
    pub fn common_flags(&self) -> u32 {
        self.common_flags
    }

    /// Returns a reference to the decompressed header data.
    #[inline]
    pub fn header_data(&self) -> &[u8] {
        &self.header_data
    }

    /// Returns the original file bytes.
    #[inline]
    pub fn file_data(&self) -> &'a [u8] {
        self.file
    }

    /// Returns the number of sections.
    #[inline]
    pub fn section_count(&self) -> usize {
        self.blocks[BlockType::Sections as usize].1.max(0) as usize
    }

    /// Returns the number of entries (instructions).
    #[inline]
    pub fn entry_count(&self) -> usize {
        self.blocks[BlockType::Entries as usize].1.max(0) as usize
    }

    /// Returns the number of pages.
    #[inline]
    pub fn page_count(&self) -> usize {
        self.blocks[BlockType::Pages as usize].1.max(0) as usize
    }

    /// Returns an iterator over install sections.
    pub fn sections(&self) -> SectionIter<'_> {
        let (offset, count) = self.blocks[BlockType::Sections as usize];
        let data = &self.header_data[offset as usize..];
        let is_unicode = matches!(
            self.encoding,
            StringEncoding::Unicode | StringEncoding::Park
        );
        SectionIter::new(data, count.max(0) as usize, self.section_size, is_unicode)
    }

    /// Returns an iterator over bytecode entries (instructions).
    pub fn entries(&self) -> EntryIter<'_> {
        let (offset, count) = self.blocks[BlockType::Entries as usize];
        let data = &self.header_data[offset as usize..];
        EntryIter::new(data, count.max(0) as usize)
    }

    /// Returns an iterator over installer pages.
    pub fn pages(&self) -> PageIter<'_> {
        let (offset, count) = self.blocks[BlockType::Pages as usize];
        let data = &self.header_data[offset as usize..];
        PageIter::new(data, count.max(0) as usize)
    }

    /// Returns an iterator over language tables.
    pub fn lang_tables(&self) -> LangTableIter<'_> {
        let (offset, count) = self.blocks[BlockType::LangTables as usize];
        let data = &self.header_data[offset as usize..];
        let entry_size = self.langtable_size.max(8) as usize;
        LangTableIter::new(data, count.max(0) as usize, entry_size)
    }

    /// Reads and decodes a string from the string table at the given offset.
    ///
    /// The `offset` is a TCHAR index into the string table, as stored in
    /// section `name_ptr` fields and entry parameter slots. For Unicode
    /// installers (NSIS 3.x), each TCHAR is 2 bytes, so the byte position
    /// is `offset * 2`. For ANSI installers, each TCHAR is 1 byte.
    pub fn read_string(&self, offset: i32) -> Result<NsisString, Error> {
        if offset < 0 {
            return Ok(NsisString {
                segments: Vec::new(),
            });
        }
        let string_block_offset = self.blocks[BlockType::Strings as usize].0 as usize;
        // name_ptr and other string offsets are TCHAR indices, not byte offsets.
        // For Unicode (UTF-16LE), multiply by 2 to get the byte offset.
        // Both Unicode and Park are UTF-16LE (char_size = 2).
        let char_size = match self.encoding {
            StringEncoding::Unicode | StringEncoding::Park => 2,
            StringEncoding::Ansi => 1,
        };
        let abs_offset = string_block_offset + (offset as usize) * char_size;
        strings::read_nsis_string(&self.header_data, abs_offset, self.encoding)
    }

    /// Returns an iterator over embedded files (`EW_EXTRACTFILE` entries).
    ///
    /// Each [`ExtractedFile`](crate::installer::ExtractedFile) provides the
    /// file name, raw data as a borrowed slice (zero-copy), and a
    /// [`decompress`](crate::installer::ExtractedFile::decompress) method.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # let data = std::fs::read("installer.exe").unwrap();
    /// # let inst = nsis::NsisInstaller::from_bytes(&data).unwrap();
    /// for file in inst.files() {
    ///     let file = file.unwrap();
    ///     println!("{}: {} bytes", file.name().unwrap(), file.data().len());
    /// }
    /// ```
    pub fn files(&self) -> FileIter<'_> {
        let (offset, count) = self.blocks[BlockType::Entries as usize];
        let data = &self.header_data[offset as usize..];
        let entries = EntryIter::new(data, count.max(0) as usize);
        FileIter::new(self, entries)
    }

    /// Normalizes a raw opcode to its V2-equivalent number.
    ///
    /// For Park version, raw opcodes are shifted due to inserted extra
    /// opcodes. This method reverses that shift. For other versions the
    /// raw opcode is returned unchanged.
    #[inline]
    pub fn normalize_opcode(&self, raw: i32) -> i32 {
        if raw < 0 {
            return raw;
        }
        if self.version == NsisVersion::Park {
            if let Some(sub) = self.park_sub {
                return opcode::normalize_park_opcode(raw as u32, sub) as i32;
            }
        }
        raw
    }

    /// Resolves an opcode index to its metadata.
    ///
    /// For Park version, the raw opcode is first normalized to its V2
    /// equivalent before lookup.
    pub fn resolve_opcode(&self, which: i32) -> Option<&'static crate::opcode::OpcodeInfo> {
        if which < 0 {
            return None;
        }
        crate::opcode::lookup_normalized(self.version, which as u32, self.park_sub)
    }

    /// Returns the data block offset within the original file (non-solid only).
    #[inline]
    pub fn data_block_offset(&self) -> usize {
        self.data_block_offset
    }

    /// Returns the decompressed solid file data (solid mode only).
    ///
    /// Each file entry in this buffer is framed with a 4-byte length prefix.
    /// Returns an empty slice for non-solid installers.
    #[inline]
    pub fn solid_data(&self) -> &[u8] {
        &self.solid_data
    }

    /// Returns an iterator over the entries belonging to the given section.
    ///
    /// Uses the section's `code` (start index) and `code_size` (count) to
    /// slice the entries block.
    pub fn section_entries(&self, section: &Section<'_>) -> EntryIter<'_> {
        let (block_offset, _) = self.blocks[BlockType::Entries as usize];
        let code = section.code().max(0) as usize;
        let count = section.code_size().max(0) as usize;
        let byte_offset = block_offset as usize + code * Entry::SIZE;
        if byte_offset < self.header_data.len() {
            EntryIter::new(&self.header_data[byte_offset..], count)
        } else {
            EntryIter::new(&[], 0)
        }
    }

    /// Returns the entry index for the `.onInit` callback.
    ///
    /// Called before the installer UI is shown. Takes no parameters and has
    /// no return value. This is the primary callback used by malware to
    /// perform early payload decryption, memory allocation, and anti-analysis
    /// checks before any user interaction.
    pub fn on_init(&self) -> Option<usize> {
        Self::callback_index(self.callbacks[0])
    }

    /// Returns the entry index for the `.onInstSuccess` callback.
    ///
    /// Called after all sections have been successfully executed. Takes no
    /// parameters. Often used by malware to launch the decrypted payload
    /// or perform cleanup after installation completes.
    pub fn on_inst_success(&self) -> Option<usize> {
        Self::callback_index(self.callbacks[1])
    }

    /// Returns the entry index for the `.onInstFailed` callback.
    ///
    /// Called when installation fails or is aborted by an error. Takes no
    /// parameters.
    pub fn on_inst_failed(&self) -> Option<usize> {
        Self::callback_index(self.callbacks[2])
    }

    /// Returns the entry index for the `.onUserAbort` callback.
    ///
    /// Called when the user clicks Cancel. Takes no parameters. Can call
    /// `Abort` to prevent the cancellation.
    pub fn on_user_abort(&self) -> Option<usize> {
        Self::callback_index(self.callbacks[3])
    }

    /// Returns the entry index for the `.onGUIInit` callback.
    ///
    /// Called after the installer dialog has been created but before it is
    /// shown. Receives `$HWNDPARENT` as the parent window handle. Used for
    /// custom UI modifications.
    pub fn on_gui_init(&self) -> Option<usize> {
        Self::callback_index(self.callbacks[4])
    }

    /// Returns the entry index for the `.onGUIEnd` callback.
    ///
    /// Called after the installer dialog is destroyed. Takes no parameters.
    pub fn on_gui_end(&self) -> Option<usize> {
        Self::callback_index(self.callbacks[5])
    }

    /// Returns the entry index for the `.onMouseOverSection` callback.
    ///
    /// Called when the mouse hovers over a section in the component page.
    /// Receives the section index in `$0`.
    pub fn on_mouse_over_section(&self) -> Option<usize> {
        Self::callback_index(self.callbacks[6])
    }

    /// Returns the entry index for the `.onVerifyInstDir` callback.
    ///
    /// Called every time the user changes the install directory. Can call
    /// `Abort` to reject the directory. Takes no parameters; the directory
    /// is in `$INSTDIR`.
    pub fn on_verify_inst_dir(&self) -> Option<usize> {
        Self::callback_index(self.callbacks[7])
    }

    /// Returns the entry index for the `.onSelChange` callback.
    ///
    /// Called when the user changes the section selection on the components
    /// page. Takes no parameters.
    pub fn on_sel_change(&self) -> Option<usize> {
        Self::callback_index(self.callbacks[8])
    }

    /// Returns the entry index for the `.onRebootFailed` callback.
    ///
    /// Called if the reboot (via `EW_REBOOT`) fails. Takes no parameters.
    pub fn on_reboot_failed(&self) -> Option<usize> {
        Self::callback_index(self.callbacks[9])
    }

    /// Returns an iterator over plugin DLL calls in the script.
    ///
    /// Yields [`crate::installer::analysis::PluginCall`] for each `EW_REGISTERDLL` entry.
    /// This is how NSIS plugins like `System.dll`, `nsDialogs.dll` are
    /// invoked.
    pub fn plugin_calls(&self) -> PluginCallIter<'_> {
        PluginCallIter::new(self, self.make_entry_iter())
    }

    /// Returns an iterator over execution commands in the script.
    ///
    /// Yields [`crate::installer::analysis::ExecCommand`] for each `EW_EXECUTE` and
    /// `EW_SHELLEXEC` entry.
    pub fn exec_commands(&self) -> ExecIter<'_> {
        ExecIter::new(self, self.make_entry_iter())
    }

    /// Returns an iterator over registry operations in the script.
    ///
    /// Yields [`crate::installer::analysis::RegistryOp`] for each `EW_WRITEREG`, `EW_DELREG`,
    /// and `EW_READREGSTR` entry.
    pub fn registry_ops(&self) -> RegistryIter<'_> {
        RegistryIter::new(self, self.make_entry_iter())
    }

    /// Returns an iterator over shortcut creation operations.
    ///
    /// Yields [`crate::installer::analysis::Shortcut`] for each `EW_CREATESHORTCUT` entry.
    pub fn shortcuts(&self) -> ShortcutIter<'_> {
        ShortcutIter::new(self, self.make_entry_iter())
    }

    /// Returns an iterator over embedded uninstaller stubs.
    ///
    /// Yields [`crate::installer::analysis::Uninstaller`] for each `EW_WRITEUNINSTALLER` entry.
    pub fn uninstallers(&self) -> UninstallerIter<'_> {
        UninstallerIter::new(self, self.make_entry_iter())
    }

    fn callback_index(val: i32) -> Option<usize> {
        if val >= 0 { Some(val as usize) } else { None }
    }

    fn make_entry_iter(&self) -> EntryIter<'_> {
        let (offset, count) = self.blocks[BlockType::Entries as usize];
        EntryIter::new(&self.header_data[offset as usize..], count.max(0) as usize)
    }
}
