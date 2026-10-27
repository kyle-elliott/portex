use super::*;

#[test]
fn test_import_descriptor_size() {
    assert_eq!(ImportDescriptor::SIZE, 20);
}

#[test]
fn test_import_descriptor_roundtrip() {
    let original = ImportDescriptor {
        original_first_thunk: 0x1000,
        time_date_stamp: 0,
        forwarder_chain: 0xFFFF_FFFF,
        name_rva: 0x2000,
        first_thunk: 0x3000,
    };

    let bytes = original.to_bytes();
    let parsed = ImportDescriptor::parse(&bytes).unwrap();
    assert_eq!(original, parsed);
}

#[test]
fn test_import_descriptor_is_null() {
    let null = ImportDescriptor::default();
    assert!(null.is_null());

    let not_null = ImportDescriptor {
        first_thunk: 0x1000,
        ..Default::default()
    };
    assert!(!not_null.is_null());
}

#[test]
fn test_thunk_ordinal_check() {
    assert!(ImportThunk::is_ordinal_entry_32(0x8000_0001));
    assert!(!ImportThunk::is_ordinal_entry_32(0x0000_1000));
    assert!(ImportThunk::is_ordinal_entry_64(0x8000_0000_0000_0001));
    assert!(!ImportThunk::is_ordinal_entry_64(0x0000_0000_0000_1000));
}

#[test]
fn test_import_table_builder_roundtrip() {
    // Create an import table.
    let mut table = ImportTable::default();
    table.add_named_import("kernel32.dll", "VirtualAlloc", 0);
    table.add_named_import("kernel32.dll", "VirtualFree", 0);
    table.add_ordinal_import("user32.dll", 123);

    assert_eq!(table.dlls.len(), 2);
    assert_eq!(table.dlls[0].imports.len(), 2);
    assert_eq!(table.dlls[1].imports.len(), 1);

    // Build the section for PE32+.
    let base_rva = 0x3000u32;
    let builder = ImportTableBuilder::new(true, base_rva);
    let size = builder.calculate_size(&table);
    assert!(size > 0);

    let (data, iat_rva, iat_size) = builder.build(&table);
    assert_eq!(data.len(), size);
    assert!(iat_rva >= base_rva);
    assert!(iat_size > 0);

    // Parse the built data again.
    let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
        if rva < base_rva {
            return None;
        }
        let offset = (rva - base_rva) as usize;
        if offset >= data.len() {
            return None;
        }
        // Return the available data, up to the requested length.
        let available = (data.len() - offset).min(len);
        Some(data[offset..offset + available].to_vec())
    };

    let parsed = ImportTable::parse(base_rva, true, read_fn).unwrap();
    assert_eq!(parsed.dlls.len(), 2);
    assert_eq!(parsed.dlls[0].name.to_lowercase(), "kernel32.dll");
    assert_eq!(parsed.dlls[0].imports.len(), 2);
    assert_eq!(parsed.dlls[1].name.to_lowercase(), "user32.dll");
    assert_eq!(parsed.dlls[1].imports.len(), 1);

    // Check the import names.
    if let ImportThunk::Name { name, .. } = &parsed.dlls[0].imports[0] {
        assert_eq!(name, "VirtualAlloc");
    } else {
        panic!("Expected named import");
    }
    if let ImportThunk::Ordinal(ord) = &parsed.dlls[1].imports[0] {
        assert_eq!(*ord, 123);
    } else {
        panic!("Expected ordinal import");
    }
}

#[test]
fn test_import_table_builder_pe32_thunks() {
    let mut table = ImportTable::default();
    table.add_named_import("kernel32.dll", "Sleep", 7);
    table.add_ordinal_import("kernel32.dll", 42);

    let base_rva = 0x2000u32;
    let (data, iat_rva, iat_size) = ImportTableBuilder::new(false, base_rva).build(&table);
    // Two thunks plus a null terminator, 4 bytes each.
    assert_eq!(iat_size, 12);

    let iat = usize::try_from(iat_rva - base_rva).unwrap();
    let thunk = |index: usize| {
        let at = iat + index * 4;
        u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
    };
    assert_eq!(thunk(1), IMAGE_ORDINAL_FLAG32 | 0x2A);
    assert_eq!(thunk(2), 0);

    let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
        let offset = usize::try_from(rva.checked_sub(base_rva)?).ok()?;
        let end = offset.checked_add(len)?.min(data.len());
        data.get(offset..end).map(<[u8]>::to_vec)
    };
    let parsed = ImportTable::parse(base_rva, false, read_fn).unwrap();
    assert_eq!(
        parsed.dlls[0].imports,
        vec![
            ImportThunk::Name {
                hint: 7,
                name: "Sleep".to_string()
            },
            ImportThunk::Ordinal(42),
        ]
    );
}

#[test]
fn test_import_table_builder_pe32_layout() {
    let mut table = ImportTable::default();
    table.add_named_import("kernel32.dll", "Sleep", 7);
    table.add_ordinal_import("kernel32.dll", 42);

    let (data, iat_rva, iat_size) = ImportTableBuilder::new(false, 0x2000).build(&table);
    // Descriptors 0..40, ILT 40..52, IAT 52..64, hint/name 64..72, DLL name 72..85.
    assert_eq!(data.len(), 85);
    assert_eq!((iat_rva, iat_size), (0x2034, 12));
    let descriptor = ImportDescriptor::parse(&data).unwrap();
    assert_eq!(
        descriptor,
        ImportDescriptor {
            original_first_thunk: 0x2028,
            time_date_stamp: 0,
            forwarder_chain: 0,
            name_rva: 0x2048,
            first_thunk: 0x2034,
        }
    );
    assert!(data[20..40].iter().all(|&byte| byte == 0));
    let thunks: Vec<u8> = [0x2040u32, 0x8000_002A, 0]
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    assert_eq!(&data[40..52], thunks.as_slice());
    assert_eq!(&data[52..64], thunks.as_slice());
    assert_eq!(&data[64..72], b"\x07\x00Sleep\0");
    assert_eq!(&data[72..], b"kernel32.dll\0");
}

#[test]
fn test_import_descriptor_write_short_buffer() {
    let mut buf = [0u8; ImportDescriptor::SIZE - 1];
    assert!(ImportDescriptor::default().write(&mut buf).is_err());
    assert!(ImportDescriptor::parse(&buf).is_err());
}
