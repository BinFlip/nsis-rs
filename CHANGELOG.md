# Changelog

All notable changes to the `nsis` crate are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-05-04

### Added

- `fmt::Display` implementations for the public diagnostic enums so
  consumers no longer need `format!("{:?}", ...)`:
  - `CompressionMethod` → `"deflate"`, `"bzip2"`, `"lzma"`, `"none"`.
  - `CompressionMode` → `"solid"`, `"non-solid"`.
  - `StringEncoding` → `"ANSI"`, `"Unicode"`, `"Park"`.
  - `NsisVersion` → `"NSIS 1"`, `"NSIS 2"`, `"NSIS 3"`, `"NSIS Park"`.
  - `RegValueType` → `"REG_SZ"`, `"REG_EXPAND_SZ"`, `"REG_BINARY"`,
    `"REG_DWORD"`, `"REG_MULTI_SZ"`, `"REG_UNKNOWN(N)"`.
- `Callback` enum (`src/installer/callback.rs`) covering the ten
  common-header callback slots (`OnInit`, `OnInstSuccess`,
  `OnInstFailed`, `OnUserAbort`, `OnGuiInit`, `OnGuiEnd`,
  `OnMouseOverSection`, `OnVerifyInstDir`, `OnSelChange`,
  `OnRebootFailed`). Provides:
  - `Callback::ALL` — all ten variants in common-header order.
  - `Callback::name()` — canonical NSIS script name (e.g. `".onInit"`).
  - `Callback::index()` — slot index (`0..10`) into the common-header
    callback array.
  - `fmt::Display` — delegates to `name()`.
- `NsisInstaller::callback(Callback) -> Option<usize>` — generic
  accessor that returns the entry index for any callback slot,
  complementing the existing per-callback `on_init()` / `on_inst_success()`
  / etc. methods.
- All standard `EW_*` opcode constants are re-exported at the crate root,
  so upstream analysis crates can match opcode numbers without importing
  the internal `opcode` module.
- `Section::contains_entry(usize) -> bool` — returns `true` when the
  given entry index falls within the section's `[code, code+code_size)`
  range. Treats negative `code`/`code_size` as zero, so consumers no
  longer need defensive `.max(0)` casts before doing range checks.
- `NsisInstaller::section_contains_entry(section_idx, entry_idx) -> bool`
  — convenience wrapper that resolves the section by index and applies
  `Section::contains_entry`.

### Changed

- The clippy panic-prevention lint set
  (`unwrap_used`, `expect_used`, `panic`, `arithmetic_side_effects`,
  `indexing_slicing`) is now declared `deny` in
  `Cargo.toml [lints.clippy]`, so the policy holds regardless of the
  consuming workspace. Previously only `missing_docs` and `unsafe_code`
  were denied (in `src/lib.rs`).
- Triage and clearance of the 310 lint violations exposed by the new
  policy. Affected files (paths relative to `src/`):
  `addressmap.rs`, `decompress/{bzip2,lzma,mod}.rs`,
  `header/{blockheader,commonheader,firstheader,mod}.rs`,
  `installer/{analysis,files,nsisinstaller}.rs`,
  `nsis/{ctlcolors,entry,langtable,page,section}.rs`,
  `opcode/mod.rs`,
  `strings/{ansi,mod,park,unicode}.rs`,
  `util.rs`.
  Patterns applied:
  - `&[u8]` indexing → `.get(...)` with `Option`/`Result` propagation.
  - Offset/size arithmetic → `checked_add` / `checked_sub` /
    `saturating_*`.
  - `.unwrap()` / `.expect()` on parse steps → `?`-propagated
    `Error` arms.
  Tests retain the convenience of `unwrap`/`expect`/`panic` via the
  `cfg_attr(test, allow(...))` escape hatch in `src/lib.rs`.

### Fixed

- Carried forward from in-progress work on `main`: park opcode mapping
  correction and uninstaller data extraction (see commit `1778513`).

## [0.1.1] - prior

- `fix: park opcode mapping`
- `fix: uninstaller data extraction`
- `feat: bump version to v0.1.1`
- `fix: docrs error on private item`
- `fix: docrs errors`

## [0.1.0] - initial release

- Initial release of the `nsis` crate.

[0.1.2]: https://github.com/BinFlip/nsis-rs/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/BinFlip/nsis-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/BinFlip/nsis-rs/releases/tag/v0.1.0
