//! Integration tests for the NSIS parser using self-built test fixtures.
//!
//! All test fixtures are built from `.nsi` scripts in `tests/build_fixtures/`
//! using `makensis` and cover specific compression/encoding/feature combinations.

use nsis::NsisInstaller;

fn parse_fixture(name: &str) -> NsisInstaller<'static> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let data: &'static [u8] = Vec::leak(data);
    NsisInstaller::from_bytes(data).unwrap_or_else(|e| panic!("failed to parse {name}: {e}"))
}

fn validate_all_structures(inst: &NsisInstaller<'_>) {
    for (i, section) in inst.sections().enumerate() {
        section.unwrap_or_else(|e| panic!("section {i} failed: {e}"));
    }
    for (i, entry) in inst.entries().enumerate() {
        entry.unwrap_or_else(|e| panic!("entry {i} failed: {e}"));
    }
    for (i, page) in inst.pages().enumerate() {
        page.unwrap_or_else(|e| panic!("page {i} failed: {e}"));
    }
}

#[test]
fn deflate_nonsolid() {
    let inst = parse_fixture("deflate_nonsolid.exe");
    assert_eq!(
        inst.compression(),
        nsis::decompress::CompressionMethod::Deflate
    );
    assert_eq!(
        inst.compression_mode(),
        nsis::decompress::CompressionMode::NonSolid
    );
    assert!(inst.section_count() > 0);
    assert!(inst.entry_count() > 0);
    validate_all_structures(&inst);
}

#[test]
fn deflate_solid() {
    let inst = parse_fixture("deflate_solid.exe");
    assert_eq!(
        inst.compression(),
        nsis::decompress::CompressionMethod::Deflate
    );
    assert_eq!(
        inst.compression_mode(),
        nsis::decompress::CompressionMode::Solid
    );
    assert!(inst.section_count() > 0);
    validate_all_structures(&inst);
}

#[test]
fn lzma_nonsolid() {
    let inst = parse_fixture("lzma_nonsolid.exe");
    assert_eq!(
        inst.compression(),
        nsis::decompress::CompressionMethod::Lzma
    );
    assert_eq!(
        inst.compression_mode(),
        nsis::decompress::CompressionMode::NonSolid
    );
    assert!(inst.section_count() > 0);
    validate_all_structures(&inst);
}

#[test]
fn lzma_solid() {
    let inst = parse_fixture("lzma_solid.exe");
    assert_eq!(
        inst.compression(),
        nsis::decompress::CompressionMethod::Lzma
    );
    assert_eq!(
        inst.compression_mode(),
        nsis::decompress::CompressionMode::Solid
    );
    assert!(inst.section_count() > 0);
    validate_all_structures(&inst);
}

#[test]
fn full_featured_sections() {
    let inst = parse_fixture("full_featured.exe");
    assert_eq!(
        inst.compression(),
        nsis::decompress::CompressionMethod::Lzma
    );
    assert_eq!(
        inst.compression_mode(),
        nsis::decompress::CompressionMode::Solid
    );
    assert_eq!(inst.section_count(), 2);
    let sections: Vec<_> = inst.sections().collect();
    let s0 = sections[0].as_ref().unwrap();
    let s1 = sections[1].as_ref().unwrap();
    let name0 = s0
        .inline_name()
        .or_else(|| inst.read_string(s0.name_ptr()).ok().map(|n| n.to_string()))
        .unwrap_or_default();
    let name1 = s1
        .inline_name()
        .or_else(|| inst.read_string(s1.name_ptr()).ok().map(|n| n.to_string()))
        .unwrap_or_default();
    assert_eq!(name0, "Core Files");
    assert_eq!(name1, "Optional Docs");
}

#[test]
fn full_featured_callbacks() {
    let inst = parse_fixture("full_featured.exe");
    assert!(inst.on_init().is_some(), "should have .onInit");
}

#[test]
fn full_featured_registry() {
    let inst = parse_fixture("full_featured.exe");
    let writes: Vec<_> = inst
        .registry_ops()
        .filter_map(|op| match op.ok()? {
            nsis::RegistryOp::Write(w) => Some(w),
            _ => None,
        })
        .collect();
    assert!(writes.len() >= 3, "should have registry writes");
    let has_version = writes.iter().any(|w| {
        w.value_name()
            .map(|n| n.to_string() == "Version")
            .unwrap_or(false)
    });
    assert!(has_version, "should write Version registry value");
}

#[test]
fn full_featured_shortcuts() {
    let inst = parse_fixture("full_featured.exe");
    let shortcuts: Vec<_> = inst.shortcuts().collect();
    assert_eq!(shortcuts.len(), 2, "should have 2 shortcuts");
}

#[test]
fn full_featured_uninstaller() {
    let inst = parse_fixture("full_featured.exe");
    let uninstallers: Vec<_> = inst.uninstallers().collect();
    assert_eq!(uninstallers.len(), 1, "should have 1 uninstaller");
    let u = uninstallers[0].as_ref().unwrap();
    let path = u.path().unwrap().to_string();
    assert!(
        path.contains("uninstall"),
        "path should contain 'uninstall', got '{path}'"
    );
}

#[test]
fn file_extraction_nonsolid() {
    let inst = parse_fixture("deflate_nonsolid.exe");
    let mut count = 0;
    for file in inst.files() {
        let file = file.unwrap();
        assert!(!file.data().is_empty(), "non-solid file should have data");
        let content = file.decompress().unwrap();
        assert!(
            !content.is_empty(),
            "decompressed content should not be empty"
        );
        count += 1;
    }
    assert!(count > 0, "should find files");
}

#[test]
fn file_extraction_solid() {
    let inst = parse_fixture("lzma_solid.exe");
    let mut count = 0;
    for file in inst.files() {
        let file = file.unwrap();
        assert!(
            !file.data().is_empty(),
            "solid file should have data from cache"
        );
        let content = file.decompress().unwrap();
        assert!(
            !content.is_empty(),
            "decompressed content should not be empty"
        );
        count += 1;
    }
    assert!(count > 0, "should find files");
}

#[test]
fn section_entries_mapping() {
    let inst = parse_fixture("full_featured.exe");
    for section in inst.sections() {
        let section = section.unwrap();
        if section.code_size() > 0 {
            let entries: Vec<_> = inst.section_entries(&section).collect();
            assert_eq!(entries.len(), section.code_size() as usize);
            for entry in &entries {
                entry.as_ref().unwrap();
            }
            return;
        }
    }
    panic!("no section with code found");
}

#[test]
fn opcode_resolution() {
    let inst = parse_fixture("full_featured.exe");
    let mut resolved = 0;
    for entry in inst.entries() {
        let entry = entry.unwrap();
        if inst.resolve_opcode(entry.which()).is_some() {
            resolved += 1;
        }
    }
    assert!(resolved > 0, "no opcodes resolved");
}

#[test]
fn string_resolution() {
    let inst = parse_fixture("full_featured.exe");
    for section in inst.sections() {
        let section = section.unwrap();
        let _ = inst.read_string(section.name_ptr());
    }
}

#[test]
fn bzip2_nonsolid() {
    let inst = parse_fixture("bzip2_nonsolid.exe");
    assert_eq!(
        inst.compression(),
        nsis::decompress::CompressionMethod::Bzip2
    );
    assert_eq!(
        inst.compression_mode(),
        nsis::decompress::CompressionMode::NonSolid
    );
    assert!(inst.section_count() > 0);
    assert!(inst.entry_count() > 0);
    validate_all_structures(&inst);
}

#[test]
fn bzip2_solid() {
    let inst = parse_fixture("bzip2_solid.exe");
    assert_eq!(
        inst.compression(),
        nsis::decompress::CompressionMethod::Bzip2
    );
    assert_eq!(
        inst.compression_mode(),
        nsis::decompress::CompressionMode::Solid
    );
    assert!(inst.section_count() > 0);
    validate_all_structures(&inst);
}

#[test]
fn bzip2_file_extraction_nonsolid() {
    let inst = parse_fixture("bzip2_nonsolid.exe");
    let mut count = 0;
    for file in inst.files() {
        let file = file.unwrap();
        assert!(
            !file.data().is_empty(),
            "bzip2 non-solid file should have data"
        );
        let content = file.decompress().unwrap();
        assert!(!content.is_empty());
        count += 1;
    }
    assert!(count > 0, "should find files");
}

#[test]
fn bzip2_file_extraction_solid() {
    let inst = parse_fixture("bzip2_solid.exe");
    let mut count = 0;
    for file in inst.files() {
        let file = file.unwrap();
        assert!(!file.data().is_empty(), "bzip2 solid file should have data");
        let content = file.decompress().unwrap();
        assert!(!content.is_empty());
        count += 1;
    }
    assert!(count > 0, "should find files");
}

#[test]
fn all_fixtures_produce_consistent_headers() {
    let fixtures = [
        "deflate_nonsolid.exe",
        "deflate_solid.exe",
        "lzma_nonsolid.exe",
        "lzma_solid.exe",
        "bzip2_nonsolid.exe",
        "bzip2_solid.exe",
        "full_featured.exe",
        "ansi_deflate.exe",
    ];
    for name in fixtures {
        let inst = parse_fixture(name);
        // All fixtures should have valid header data.
        assert!(
            inst.header_data().len() >= 68,
            "{name}: header too short ({})",
            inst.header_data().len()
        );
        // All should have at least one section.
        assert!(inst.section_count() > 0, "{name}: no sections");
        // All should have entries.
        assert!(inst.entry_count() > 0, "{name}: no entries");
        // All structures should parse without errors.
        validate_all_structures(&inst);
    }
}

#[test]
fn all_fixtures_extract_files() {
    let fixtures = [
        "deflate_nonsolid.exe",
        "deflate_solid.exe",
        "lzma_nonsolid.exe",
        "lzma_solid.exe",
        "bzip2_nonsolid.exe",
        "bzip2_solid.exe",
        "full_featured.exe",
    ];
    for name in fixtures {
        let inst = parse_fixture(name);
        let mut file_count = 0;
        for file in inst.files() {
            let file = file.unwrap();
            let content = file.decompress().unwrap();
            assert!(!content.is_empty(), "{name}: decompressed file is empty");
            file_count += 1;
        }
        assert!(file_count > 0, "{name}: no files extracted");
    }
}

#[test]
fn extracted_file_content_is_valid() {
    // Our fixtures contain payload.txt with known content.
    let inst = parse_fixture("deflate_nonsolid.exe");
    for file in inst.files() {
        let file = file.unwrap();
        let name = file.name().unwrap().to_string();
        if name.contains("payload.txt") {
            let content = file.decompress().unwrap();
            let text = String::from_utf8_lossy(&content);
            assert!(
                text.contains("test payload"),
                "payload.txt should contain 'test payload', got: {text}"
            );
            return;
        }
    }
    panic!("payload.txt not found in fixture");
}

#[test]
fn solid_and_nonsolid_produce_same_content() {
    // Compare extracted payload.txt between solid and non-solid deflate.
    let nonsolid = parse_fixture("deflate_nonsolid.exe");
    let solid = parse_fixture("deflate_solid.exe");

    let get_payload = |inst: &nsis::NsisInstaller<'_>| -> Vec<u8> {
        for file in inst.files() {
            let file = file.unwrap();
            let name = file.name().unwrap().to_string();
            if name.contains("payload.txt") {
                return file.decompress().unwrap();
            }
        }
        panic!("payload.txt not found");
    };

    let ns_content = get_payload(&nonsolid);
    let s_content = get_payload(&solid);
    assert_eq!(
        ns_content, s_content,
        "solid and non-solid should produce identical payload content"
    );
}

#[test]
fn all_compression_methods_produce_same_content() {
    // Compare payload.txt across all 6 compression variants.
    let fixtures = [
        "deflate_nonsolid.exe",
        "deflate_solid.exe",
        "lzma_nonsolid.exe",
        "lzma_solid.exe",
        "bzip2_nonsolid.exe",
        "bzip2_solid.exe",
    ];

    let mut reference: Option<Vec<u8>> = None;
    for name in fixtures {
        let inst = parse_fixture(name);
        for file in inst.files() {
            let file = file.unwrap();
            let fname = file.name().unwrap().to_string();
            if fname.contains("payload.txt") {
                let content = file.decompress().unwrap();
                if let Some(ref expected) = reference {
                    assert_eq!(
                        &content, expected,
                        "{name}: payload.txt differs from deflate_nonsolid"
                    );
                } else {
                    reference = Some(content);
                }
                break;
            }
        }
    }
    assert!(reference.is_some(), "no payload.txt found in any fixture");
}
