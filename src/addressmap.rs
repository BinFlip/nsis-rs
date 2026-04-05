//! PE overlay detection for NSIS installers.
//!
//! NSIS installation data is appended as a PE overlay after the last PE section.
//! This module locates the overlay start and provides access to the overlay bytes.

use crate::error::Error;

/// Provides access to the PE overlay region of an NSIS installer.
///
/// The overlay is the region of the file after the last PE section's raw data.
/// NSIS appends all installation data (FirstHeader, compressed headers, data block)
/// in this region.
///
/// # Example
///
/// ```no_run
/// use nsis::addressmap::PeOverlay;
///
/// let file = std::fs::read("installer.exe").unwrap();
/// let overlay = PeOverlay::from_bytes(&file).unwrap();
/// println!("Overlay starts at offset 0x{:X}", overlay.overlay_offset());
/// println!("Overlay size: {} bytes", overlay.overlay().len());
/// ```
pub struct PeOverlay<'a> {
    file: &'a [u8],
    overlay_offset: usize,
}

impl<'a> PeOverlay<'a> {
    /// Parses the PE headers and locates the overlay region.
    ///
    /// Returns an error if the file is not a valid PE32 executable or
    /// if no overlay data exists after the PE sections.
    pub fn from_bytes(file: &'a [u8]) -> Result<Self, Error> {
        let pe = goblin::pe::PE::parse(file).map_err(Error::from)?;
        Self::from_goblin(file, &pe)
    }

    /// Locates the overlay region using a pre-parsed goblin PE.
    ///
    /// This is useful when the caller already has a parsed PE and wants to
    /// avoid re-parsing.
    pub fn from_goblin(file: &'a [u8], pe: &goblin::pe::PE<'_>) -> Result<Self, Error> {
        // Validate PE32 (not PE32+).
        if let Some(oh) = pe.header.optional_header {
            let magic = oh.standard_fields.magic;
            if magic != goblin::pe::optional_header::MAGIC_32 {
                return Err(Error::Not32Bit { magic });
            }
        }

        // Find the end of the last PE section's raw data.
        let overlay_offset = pe
            .sections
            .iter()
            .map(|s| (s.pointer_to_raw_data as usize).saturating_add(s.size_of_raw_data as usize))
            .max()
            .unwrap_or(0);

        if overlay_offset == 0 || overlay_offset >= file.len() {
            return Err(Error::OverlayNotFound);
        }

        Ok(Self {
            file,
            overlay_offset,
        })
    }

    /// Returns the overlay bytes (everything after the last PE section).
    pub fn overlay(&self) -> &'a [u8] {
        &self.file[self.overlay_offset..]
    }

    /// Returns the byte offset where the overlay begins in the file.
    pub fn overlay_offset(&self) -> usize {
        self.overlay_offset
    }

    /// Returns `true` if the PE contains a `.ndata` section.
    ///
    /// Per SANS ISC: "NSIS-created executables contain a distinctive section
    /// named '.ndata'." This is a quick heuristic to check if a PE is likely
    /// an NSIS installer before attempting full parsing.
    pub fn has_ndata_section(pe: &goblin::pe::PE<'_>) -> bool {
        pe.sections.iter().any(|s| {
            let name = s.name().unwrap_or("");
            name == ".ndata"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_not_found_on_empty() {
        // A buffer too small to be a valid PE.
        let data = [0u8; 64];
        let result = PeOverlay::from_bytes(&data);
        assert!(result.is_err());
    }
}
