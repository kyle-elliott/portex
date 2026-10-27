use super::*;

/// Return a reader over `data` that starts at `base_rva`.
fn reader(data: &[u8], base_rva: u32) -> impl Fn(u32, usize) -> Option<Vec<u8>> + '_ {
    move |rva: u32, len: usize| {
        let offset = usize::try_from(rva.checked_sub(base_rva)?).ok()?;
        let rest = data.get(offset..)?;
        if rest.is_empty() {
            return None;
        }
        Some(rest.get(..len.min(rest.len()))?.to_vec())
    }
}

#[test]
fn test_export_directory_size() {
    assert_eq!(ExportDirectory::SIZE, 40);
}

#[test]
fn test_export_directory_roundtrip() {
    let original = ExportDirectory {
        characteristics: 0,
        time_date_stamp: 0x1234_5678,
        major_version: 1,
        minor_version: 0,
        name_rva: 0x1000,
        base: 1,
        number_of_functions: 10,
        number_of_names: 8,
        address_of_functions: 0x2000,
        address_of_names: 0x3000,
        address_of_name_ordinals: 0x4000,
    };

    let bytes = original.to_bytes();
    let parsed = ExportDirectory::parse(&bytes).unwrap();
    assert_eq!(original, parsed);
}

#[test]
fn test_export_table_builder_roundtrip() {
    // Create an export table
    let mut table = ExportTable::default();
    table.set_dll_name("test.dll");
    table.set_base(1);
    table.add_export(Some("FunctionA"), 0x1000);
    table.add_export(Some("FunctionB"), 0x2000);
    table.add_export(None, 0x3000); // Export by ordinal only

    assert_eq!(table.exports.len(), 3);
    assert_eq!(table.dll_name, "test.dll");

    // Build the section
    let base_rva = 0x4000u32;
    let builder = ExportTableBuilder::new(base_rva);
    let size = ExportTableBuilder::calculate_size(&table);
    assert!(size > 0);

    let (data, export_size) = builder.build(&table);
    assert_eq!(data.len(), size);
    assert!(export_size > 0);

    // Parse the built data back
    let parsed = ExportTable::parse(base_rva, export_size, reader(&data, base_rva)).unwrap();
    assert_eq!(parsed.dll_name, "test.dll");
    assert_eq!(parsed.exports.len(), 3);

    // Verify named exports
    let func_a = parsed.find_by_name("FunctionA");
    assert!(func_a.is_some());
    if let ExportAddress::Rva(rva) = &func_a.unwrap().address {
        assert_eq!(*rva, 0x1000);
    } else {
        panic!("Expected RVA export");
    }

    let func_b = parsed.find_by_name("FunctionB");
    assert!(func_b.is_some());
}

#[test]
fn try_add_export_rejects_ordinal_overflow() {
    let mut table = ExportTable::default();
    table.set_base(u32::MAX);
    table.try_add_export(Some("Last"), 0x1000).unwrap();
    assert_eq!(table.exports[0].ordinal, u32::MAX);

    let err = table.try_add_export(Some("Next"), 0x2000).unwrap_err();
    assert!(matches!(
        err.kind(),
        crate::ErrorKind::InvalidDataDirectory(_)
    ));
    let err = table.try_add_forwarder(None, "OTHER.Func").unwrap_err();
    assert!(matches!(
        err.kind(),
        crate::ErrorKind::InvalidDataDirectory(_)
    ));
    assert_eq!(table.exports.len(), 1);
}

#[test]
fn try_build_accepts_unnamed_export_above_u16_index() {
    let high_ordinal = 1 + 70_000;
    let table = ExportTable {
        directory: ExportDirectory {
            base: 1,
            ..ExportDirectory::default()
        },
        dll_name: "sparse.dll".to_string(),
        exports: vec![
            ExportedFunction {
                ordinal: 1,
                name: Some("First".to_string()),
                aliases: Vec::new(),
                address: ExportAddress::Rva(0x1000),
            },
            ExportedFunction {
                ordinal: high_ordinal,
                name: None,
                aliases: Vec::new(),
                address: ExportAddress::Rva(0x2000),
            },
        ],
    };

    let base_rva = 0x10_0000u32;
    let (data, export_size) = ExportTableBuilder::new(base_rva).try_build(&table).unwrap();
    let parsed = ExportTable::parse(base_rva, export_size, reader(&data, base_rva)).unwrap();
    assert_eq!(parsed.exports.len(), 2);
    assert_eq!(
        parsed.find_by_ordinal(high_ordinal).map(|e| &e.address),
        Some(&ExportAddress::Rva(0x2000))
    );
    assert_eq!(parsed.find_by_name("First").map(|e| e.ordinal), Some(1));
}

#[test]
fn try_build_writes_forwarders_and_aliases() {
    let mut table = ExportTable::default();
    table.set_dll_name("fwd.dll");
    table.set_base(5);
    table
        .try_add_forwarder(Some("Alloc"), "NTDLL.RtlAllocateHeap")
        .unwrap();
    table.try_add_export(Some("Beta"), 0x3000).unwrap();
    table.exports[1].aliases.push("Alpha".to_string());
    // Three names refer to two functions.

    let base_rva = 0x2000u32;
    let (data, export_size) = ExportTableBuilder::new(base_rva).try_build(&table).unwrap();
    let parsed = ExportTable::parse(base_rva, export_size, reader(&data, base_rva)).unwrap();
    assert_eq!(parsed.dll_name, "fwd.dll");
    assert_eq!(
        parsed.find_by_name("Alloc").map(|e| &e.address),
        Some(&ExportAddress::Forwarder(
            "NTDLL.RtlAllocateHeap".to_string()
        ))
    );
    assert_eq!(parsed.find_by_name("Alpha").map(|e| e.ordinal), Some(6));
    assert_eq!(parsed.find_by_name("Beta").map(|e| e.ordinal), Some(6));
}
