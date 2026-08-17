use anyhow::{Context, Result, bail, ensure};

/// The firmware is mapped so that it ends at the 4 GiB boundary.
const FOUR_GIB: u64 = 0x1_0000_0000;

/// The GUIDed table sits 32 bytes before the end of the image, and each entry
/// is a two byte length followed by a GUID.
const FOOTER_OFFSET_FROM_END: usize = 32;
const ENTRY_HEADER_LEN: usize = 18;

const TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
const SEV_HASH_TABLE_RV_GUID: &str = "7255371f-3a3b-4b04-927b-1da6efa8d454";
const SEV_ES_RESET_BLOCK_GUID: &str = "00f771de-1a7e-4fcb-890e-68c77e2fb44e";
const SEV_METADATA_GUID: &str = "dc886566-984a-4798-a75e-5585a7bf67cc";

/// Sections declared by the OVMF SEV metadata table, as built by
/// OvmfPkg/ResetVector/X64/OvmfSevMetadata.asm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    SecMem,
    Secrets,
    Cpuid,
    SvsmCaa,
    KernelHashes,
}

impl SectionType {
    fn from_raw(raw: u32) -> Result<Self> {
        Ok(match raw {
            1 => Self::SecMem,
            2 => Self::Secrets,
            3 => Self::Cpuid,
            4 => Self::SvsmCaa,
            0x10 => Self::KernelHashes,
            other => bail!("OVMF metadata declares unknown section type {other}"),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MetadataSection {
    pub gpa: u64,
    pub size: u64,
    pub section_type: SectionType,
}

pub struct Ovmf {
    data: Vec<u8>,
    gpa: u64,
    table: Vec<([u8; 16], Vec<u8>)>,
    metadata: Vec<MetadataSection>,
}

impl Ovmf {
    pub fn parse(data: &[u8]) -> Result<Self> {
        ensure!(
            data.len().is_multiple_of(super::gctx::PAGE_SIZE),
            "firmware image is not a whole number of pages"
        );
        let gpa = FOUR_GIB
            .checked_sub(data.len() as u64)
            .context("firmware image is larger than the guest address space below 4 GiB")?;
        let table = parse_footer_table(data)?;
        let metadata = parse_metadata(data, &table)?;
        Ok(Self {
            data: data.to_vec(),
            gpa,
            table,
            metadata,
        })
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn gpa(&self) -> u64 {
        self.gpa
    }

    pub fn metadata(&self) -> &[MetadataSection] {
        &self.metadata
    }

    pub fn has_section(&self, section_type: SectionType) -> bool {
        self.metadata
            .iter()
            .any(|section| section.section_type == section_type)
    }

    /// Where QEMU writes the table of kernel, initrd and cmdline hashes for
    /// measured direct boot. Without it the firmware boots whatever the host
    /// hands it and the measurement covers none of it.
    pub fn sev_hashes_table_gpa(&self) -> Result<u64> {
        let entry = self
            .table_item(SEV_HASH_TABLE_RV_GUID)
            .context("firmware has no SEV hashes table entry")?;
        Ok(u64::from(read_u32(entry, 0)?))
    }

    /// The reset address the application processors start at, which sets the
    /// code segment and instruction pointer in every non-boot VMSA.
    pub fn sev_es_reset_eip(&self) -> Result<u32> {
        let entry = self
            .table_item(SEV_ES_RESET_BLOCK_GUID)
            .context("firmware has no SEV-ES reset block")?;
        read_u32(entry, 0)
    }

    fn table_item(&self, guid: &str) -> Option<&[u8]> {
        let wanted = guid_le(guid);
        self.table
            .iter()
            .find(|(candidate, _)| *candidate == wanted)
            .map(|(_, data)| data.as_slice())
    }
}

fn parse_footer_table(data: &[u8]) -> Result<Vec<([u8; 16], Vec<u8>)>> {
    let mut table = Vec::new();
    let Some(footer_start) = data
        .len()
        .checked_sub(FOOTER_OFFSET_FROM_END + ENTRY_HEADER_LEN)
    else {
        return Ok(table);
    };

    let footer = &data[footer_start..footer_start + ENTRY_HEADER_LEN];
    if footer[2..] != guid_le(TABLE_FOOTER_GUID) {
        return Ok(table);
    }
    let footer_size = u16::from_le_bytes([footer[0], footer[1]]) as usize;
    let Some(table_size) = footer_size.checked_sub(ENTRY_HEADER_LEN) else {
        return Ok(table);
    };
    let table_start = footer_start
        .checked_sub(table_size)
        .context("firmware GUIDed table claims to start before the image does")?;

    // Entries are walked backwards from the footer, each one declaring the
    // total size of the entry that precedes it.
    let mut rest = &data[table_start..footer_start];
    while rest.len() >= ENTRY_HEADER_LEN {
        let header = &rest[rest.len() - ENTRY_HEADER_LEN..];
        let entry_size = u16::from_le_bytes([header[0], header[1]]) as usize;
        ensure!(
            entry_size >= ENTRY_HEADER_LEN && entry_size <= rest.len(),
            "firmware GUIDed table has an entry of size {entry_size}"
        );
        let mut guid = [0_u8; 16];
        guid.copy_from_slice(&header[2..]);
        let body = rest[rest.len() - entry_size..rest.len() - ENTRY_HEADER_LEN].to_vec();
        table.push((guid, body));
        rest = &rest[..rest.len() - entry_size];
    }

    Ok(table)
}

fn parse_metadata(data: &[u8], table: &[([u8; 16], Vec<u8>)]) -> Result<Vec<MetadataSection>> {
    let wanted = guid_le(SEV_METADATA_GUID);
    let Some((_, entry)) = table.iter().find(|(guid, _)| *guid == wanted) else {
        return Ok(Vec::new());
    };

    let offset_from_end = read_u32(entry, 0)? as usize;
    let start = data
        .len()
        .checked_sub(offset_from_end)
        .context("OVMF metadata offset points outside the image")?;
    let header = data
        .get(start..start + 16)
        .context("OVMF metadata header is truncated")?;
    ensure!(&header[..4] == b"ASEV", "OVMF metadata signature is wrong");
    let size = read_u32(header, 4)? as usize;
    ensure!(read_u32(header, 8)? == 1, "OVMF metadata version is not 1");
    let items = read_u32(header, 12)? as usize;

    let body = data
        .get(start + 16..start + size)
        .context("OVMF metadata table is truncated")?;
    let mut sections = Vec::with_capacity(items);
    for index in 0..items {
        let descriptor = body
            .get(index * 12..index * 12 + 12)
            .context("OVMF metadata declares more sections than it carries")?;
        sections.push(MetadataSection {
            gpa: u64::from(read_u32(descriptor, 0)?),
            size: u64::from(read_u32(descriptor, 4)?),
            section_type: SectionType::from_raw(read_u32(descriptor, 8)?)?,
        });
    }
    Ok(sections)
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .context("firmware structure is truncated")?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// EFI stores a GUID with its first three groups little endian, so the byte
/// order in the image is not the order the text form reads in.
pub(crate) fn guid_le(guid: &str) -> [u8; 16] {
    let digits: Vec<u8> = guid
        .bytes()
        .filter(|byte| *byte != b'-')
        .map(|byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("{guid} is not a GUID"),
        })
        .collect();
    assert_eq!(digits.len(), 32, "{guid} is not a GUID");

    let mut raw = [0_u8; 16];
    for (index, pair) in digits.chunks_exact(2).enumerate() {
        raw[index] = (pair[0] << 4) | pair[1];
    }
    raw[0..4].reverse();
    raw[4..6].reverse();
    raw[6..8].reverse();
    raw
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_guid_is_stored_mixed_endian() {
        assert_eq!(
            guid_le("96b582de-1fb2-45f7-baea-a366c55a082d"),
            [
                0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a,
                0x08, 0x2d
            ]
        );
    }
}
