use super::{
    Error, Resource, ResourceDataEntry, ResourceDirectory, ResourceDirectoryEntry,
    ResourceDirectoryHeader, ResourceId, ResourceType, Result, checked_resource_rva,
};
use crate::prelude::*;

/// Maximum number of directory entries that the parser visits, for all tree levels together.
const MAX_VISITED_ENTRIES: usize = 262_144;

impl ResourceDirectory {
    /// Parse the resource directory from PE data.
    ///
    /// `rsrc_rva` is the RVA of the resource directory, and `rsrc_size` is its size in bytes.
    /// `read_at_rva(rva, len)` must return `len` bytes at the RVA `rva`. It must return `None`
    /// if it cannot read the range. This function does not load the resource payloads.
    ///
    /// # Errors
    ///
    /// Returns an invalid-RVA error if a directory structure cannot be read.
    ///
    /// Returns an invalid-data-directory error if one of these conditions is true:
    /// - `rsrc_size` is smaller than an `IMAGE_RESOURCE_DIRECTORY`.
    /// - The tree has more than 262,144 entries.
    /// - A structure or a name is outside `rsrc_size`.
    /// - The named entries do not come before the ID entries.
    /// - A type entry or a name entry does not point to a subdirectory.
    /// - A language entry is named or points to a subdirectory.
    /// - A numeric ID has high bits that are not zero.
    /// - A name is not valid UTF-16.
    /// - The reserved field of a data entry is not zero.
    /// - Two entries have the same type, name and language.
    pub fn parse<F>(rsrc_rva: u32, rsrc_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        if usize::try_from(rsrc_size).is_ok_and(|size| size < ResourceDirectoryHeader::SIZE) {
            return Err(Error::invalid_data_directory(format!(
                "resource directory is {} bytes, expected at least {}",
                rsrc_size,
                ResourceDirectoryHeader::SIZE
            )));
        }
        let mut walker = ResourceTreeWalker {
            rsrc_rva,
            rsrc_size,
            read_at_rva: &read_at_rva,
            visited_entries: 0,
            seen_resources: BTreeSet::new(),
            resources: Vec::new(),
        };
        walker.walk_types()?;
        Ok(Self {
            resources: walker.resources,
        })
    }

    /// Parse the resource directory from PE data, and load the resource data.
    ///
    /// Unlike `parse()`, this function also loads the resource data into each `Resource`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::parse`] and [`Self::try_load_data`].
    pub fn parse_with_data<F>(rsrc_rva: u32, rsrc_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut dir = Self::parse(rsrc_rva, rsrc_size, &read_at_rva)?;
        dir.try_load_data(&read_at_rva)?;
        Ok(dir)
    }

    /// Load the data for each resource that does not have data yet.
    ///
    /// Use this function after `parse()` to load the resource data later.
    pub fn load_data<F>(&mut self, read_at_rva: F)
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        for resource in &mut self.resources {
            if resource.data.is_none() && resource.size > 0 {
                resource.data = read_at_rva(resource.data_rva, resource.size as usize);
            }
        }
    }

    /// Load all resource payloads. Stop at the first range that cannot be read.
    ///
    /// `read_at_rva(rva, len)` reads `len` bytes at the RVA `rva`.
    ///
    /// # Errors
    ///
    /// Returns an invalid-RVA error if `read_at_rva` cannot read a payload. Returns an
    /// invalid-data-directory error if `read_at_rva` returns a length that is not equal to the
    /// size in the data entry.
    pub fn try_load_data<F>(&mut self, read_at_rva: F) -> Result<()>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        for resource in &mut self.resources {
            if resource.data.is_none() && resource.size > 0 {
                resource.data = Some(crate::parse_utils::read_exact_rva(
                    &read_at_rva,
                    resource.data_rva,
                    resource.size as usize,
                    "resource payload",
                )?);
            }
        }
        Ok(())
    }

    /// Find all resources of a resource type.
    #[must_use]
    pub fn find_by_type(&self, rt: ResourceType) -> Vec<&Resource> {
        self.resources.iter().filter(|r| r.is_type(rt)).collect()
    }

    /// Get the first manifest resource, if there is one.
    #[must_use]
    pub fn manifest(&self) -> Option<&Resource> {
        self.find_by_type(ResourceType::Manifest).first().copied()
    }

    /// Get the first version information resource, if there is one.
    #[must_use]
    pub fn version_info(&self) -> Option<&Resource> {
        self.find_by_type(ResourceType::Version).first().copied()
    }

    /// Get all icon resources.
    #[must_use]
    pub fn icons(&self) -> Vec<&Resource> {
        self.find_by_type(ResourceType::Icon)
    }

    /// Get all icon group resources.
    #[must_use]
    pub fn icon_groups(&self) -> Vec<&Resource> {
        self.find_by_type(ResourceType::GroupIcon)
    }

    /// Check if the directory has no resources.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    /// Get the number of resources.
    #[must_use]
    pub fn len(&self) -> usize {
        self.resources.len()
    }
}

/// A level of the resource tree. The tree has three levels.
#[derive(Debug, Clone, Copy)]
enum TreeLevel {
    Type,
    Name,
    Language,
}

impl TreeLevel {
    /// Context text for range errors on the directory entries of this level.
    fn entry_context(self) -> &'static str {
        match self {
            Self::Type => "resource type entry",
            Self::Name => "resource name entry",
            Self::Language => "resource language entry",
        }
    }

    /// Context text for errors when the named entries of this level do not come first.
    fn order_context(self) -> &'static str {
        match self {
            Self::Type => "resource type",
            Self::Name => "resource name",
            Self::Language => "resource language",
        }
    }
}

/// A walk over the resource tree, with a limit on the number of entries. The walk collects
/// the leaf resources.
struct ResourceTreeWalker<'a, F> {
    rsrc_rva: u32,
    rsrc_size: u32,
    read_at_rva: &'a F,
    visited_entries: usize,
    seen_resources: BTreeSet<(ResourceId, ResourceId, u16)>,
    resources: Vec<Resource>,
}

impl<F> ResourceTreeWalker<'_, F>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    /// Walk the root (type) directory and everything below it.
    fn walk_types(&mut self) -> Result<()> {
        let root_rva = self.rsrc_rva;
        let root_header = self.read_header(root_rva)?;
        for i in 0..root_header.total_entries() {
            let type_entry = self.read_entry(root_rva, &root_header, i, TreeLevel::Type)?;
            let type_id = self.parse_resource_id(type_entry)?;

            if !type_entry.is_directory() {
                return Err(Error::invalid_data_directory(
                    "resource type entry must point to a subdirectory",
                ));
            }

            let name_dir_rva = checked_resource_rva(
                self.rsrc_rva,
                self.rsrc_size,
                type_entry.data_offset(),
                ResourceDirectoryHeader::SIZE,
                "resource name directory",
            )?;
            self.walk_names(&type_id, name_dir_rva)?;
        }
        Ok(())
    }

    /// Walk a level-2 (name) directory and its language directories.
    fn walk_names(&mut self, type_id: &ResourceId, dir_rva: u32) -> Result<()> {
        let header = self.read_header(dir_rva)?;
        for j in 0..header.total_entries() {
            let name_entry = self.read_entry(dir_rva, &header, j, TreeLevel::Name)?;
            let name_id = self.parse_resource_id(name_entry)?;

            if !name_entry.is_directory() {
                return Err(Error::invalid_data_directory(
                    "resource name entry must point to a subdirectory",
                ));
            }

            let lang_dir_rva = checked_resource_rva(
                self.rsrc_rva,
                self.rsrc_size,
                name_entry.data_offset(),
                ResourceDirectoryHeader::SIZE,
                "resource language directory",
            )?;
            self.walk_languages(type_id, &name_id, lang_dir_rva)?;
        }
        Ok(())
    }

    /// Walk a level-3 (language) directory, recording one resource per entry.
    fn walk_languages(
        &mut self,
        type_id: &ResourceId,
        name_id: &ResourceId,
        dir_rva: u32,
    ) -> Result<()> {
        let header = self.read_header(dir_rva)?;
        for k in 0..header.total_entries() {
            let lang_entry = self.read_entry(dir_rva, &header, k, TreeLevel::Language)?;

            if lang_entry.is_named() {
                return Err(Error::invalid_data_directory(
                    "resource language entry must use an integer identifier",
                ));
            }
            let language = lang_entry.id();

            if lang_entry.is_directory() {
                return Err(Error::invalid_data_directory(
                    "resource language entry must point to a data entry",
                ));
            }

            let data_entry_rva = checked_resource_rva(
                self.rsrc_rva,
                self.rsrc_size,
                lang_entry.data_offset(),
                ResourceDataEntry::SIZE,
                "resource data entry",
            )?;
            let data_entry_data = (self.read_at_rva)(data_entry_rva, ResourceDataEntry::SIZE)
                .ok_or_else(|| Error::invalid_rva(data_entry_rva))?;
            let data_entry = ResourceDataEntry::parse(&data_entry_data)?;
            if data_entry.reserved != 0 {
                return Err(Error::invalid_data_directory(
                    "resource data-entry reserved field must be zero",
                ));
            }
            if !self
                .seen_resources
                .insert((type_id.clone(), name_id.clone(), language))
            {
                return Err(Error::invalid_data_directory(
                    "duplicate resource type/name/language entry",
                ));
            }

            self.resources.push(Resource {
                type_id: type_id.clone(),
                name: name_id.clone(),
                language,
                data_rva: data_entry.offset_to_data,
                size: data_entry.size,
                code_page: data_entry.code_page,
                data: None,
            });
        }
        Ok(())
    }

    /// Read the `IMAGE_RESOURCE_DIRECTORY` at `dir_rva`.
    fn read_header(&self, dir_rva: u32) -> Result<ResourceDirectoryHeader> {
        let data = (self.read_at_rva)(dir_rva, ResourceDirectoryHeader::SIZE)
            .ok_or_else(|| Error::invalid_rva(dir_rva))?;
        ResourceDirectoryHeader::parse(&data)
    }

    /// Read entry `index` of the directory at the RVA `dir_rva`.
    ///
    /// This function enforces the limit on visited entries, the directory bounds and the
    /// order of the entries (named entries first).
    fn read_entry(
        &mut self,
        dir_rva: u32,
        header: &ResourceDirectoryHeader,
        index: usize,
        level: TreeLevel,
    ) -> Result<ResourceDirectoryEntry> {
        self.visited_entries += 1;
        if self.visited_entries > MAX_VISITED_ENTRIES {
            return Err(Error::invalid_data_directory(
                "resource tree exceeds the entry limit",
            ));
        }
        let directory_relative = dir_rva
            .checked_sub(self.rsrc_rva)
            .ok_or_else(|| Error::invalid_data_directory("resource directory precedes its base"))?;
        let entry_relative = index
            .checked_mul(ResourceDirectoryEntry::SIZE)
            .and_then(|offset| offset.checked_add(ResourceDirectoryHeader::SIZE))
            .and_then(|offset| u32::try_from(offset).ok())
            .and_then(|offset| directory_relative.checked_add(offset))
            .ok_or_else(|| Error::invalid_data_directory("resource entry offset overflow"))?;
        let entry_rva = checked_resource_rva(
            self.rsrc_rva,
            self.rsrc_size,
            entry_relative,
            ResourceDirectoryEntry::SIZE,
            level.entry_context(),
        )?;
        let entry_data = (self.read_at_rva)(entry_rva, ResourceDirectoryEntry::SIZE)
            .ok_or_else(|| Error::invalid_rva(entry_rva))?;
        let entry = ResourceDirectoryEntry::parse(&entry_data)?;
        validate_resource_entry_order(index, header, entry, level.order_context())?;
        Ok(entry)
    }

    /// Decode the name or numeric ID of a type or name entry.
    fn parse_resource_id(&self, entry: ResourceDirectoryEntry) -> Result<ResourceId> {
        if !entry.is_named() {
            if entry.name_or_id & 0xffff_0000 != 0 {
                return Err(Error::invalid_data_directory(
                    "numeric resource identifier has nonzero reserved bits",
                ));
            }
            return Ok(ResourceId::Id(entry.id()));
        }

        let name_offset = checked_resource_rva(
            self.rsrc_rva,
            self.rsrc_size,
            entry.name_offset(),
            2,
            "resource name length",
        )?;
        // A resource name is a Unicode string with a length prefix.
        let len_data = crate::parse_utils::read_exact_rva(
            self.read_at_rva,
            name_offset,
            2,
            "resource name length",
        )?;
        let len = usize::from(u16::from_le_bytes([len_data[0], len_data[1]]));
        let byte_len = len
            .checked_mul(2)
            .ok_or_else(|| Error::invalid_data_directory("resource name length overflow"))?;
        let string_relative = entry
            .name_offset()
            .checked_add(2)
            .ok_or_else(|| Error::invalid_data_directory("resource name offset overflow"))?;
        let string_rva = checked_resource_rva(
            self.rsrc_rva,
            self.rsrc_size,
            string_relative,
            byte_len,
            "resource name",
        )?;
        let name_data = crate::parse_utils::read_exact_rva(
            self.read_at_rva,
            string_rva,
            byte_len,
            "resource name",
        )?;

        // Convert the UTF-16LE units to a `String`.
        let chars: Vec<u16> = name_data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .collect();
        let name = String::from_utf16(&chars)
            .map_err(|_| Error::invalid_data_directory("resource name contains invalid UTF-16"))?;
        Ok(ResourceId::Name(name))
    }
}

fn validate_resource_entry_order(
    index: usize,
    header: &ResourceDirectoryHeader,
    entry: ResourceDirectoryEntry,
    context: &str,
) -> Result<()> {
    let should_be_named = index < usize::from(header.number_of_named_entries);
    if entry.is_named() != should_be_named {
        return Err(Error::invalid_data_directory(format!(
            "{context} entries are not ordered with named entries first"
        )));
    }
    Ok(())
}
