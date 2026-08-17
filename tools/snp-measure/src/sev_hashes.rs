use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};

use crate::gctx::PAGE_SIZE;
use crate::ovmf::guid_le;

const TABLE_HEADER_GUID: &str = "9438d606-4f22-4cc9-b479-a793d411fd21";
const KERNEL_ENTRY_GUID: &str = "4de79437-abd2-427f-b835-d5b172d2045b";
const INITRD_ENTRY_GUID: &str = "44baf731-3a2f-4bd7-9af1-41e29169781d";
const CMDLINE_ENTRY_GUID: &str = "97d02dd8-bd20-4c94-aa78-e7714d36ab2a";

const ENTRY_LEN: u16 = 50;
const TABLE_LEN: u16 = 168;
const PADDED_TABLE_LEN: usize = 176;

/// The kernel, initrd and command line the firmware is allowed to boot. QEMU
/// writes this table into the guest before launch and the firmware refuses
/// anything whose hash is not in it, which is how a direct boot ends up inside
/// the launch measurement rather than beside it.
pub struct SevHashes {
    kernel: [u8; 32],
    initrd: [u8; 32],
    cmdline: [u8; 32],
}

impl SevHashes {
    pub fn new(kernel: &[u8], initrd: &[u8], cmdline: Option<&str>) -> Self {
        // The firmware hashes the command line with its terminator, so an
        // absent command line is one NUL rather than nothing at all.
        let mut terminated = cmdline.unwrap_or("").as_bytes().to_vec();
        terminated.push(0);
        Self {
            kernel: Sha256::digest(kernel).into(),
            initrd: Sha256::digest(initrd).into(),
            cmdline: Sha256::digest(&terminated).into(),
        }
    }

    /// Byte for byte what QEMU builds. A difference here is a measurement that
    /// disagrees with every real launch.
    pub fn table(&self) -> Vec<u8> {
        let mut table = Vec::with_capacity(PADDED_TABLE_LEN);
        table.extend_from_slice(&guid_le(TABLE_HEADER_GUID));
        table.extend_from_slice(&TABLE_LEN.to_le_bytes());
        push_entry(&mut table, CMDLINE_ENTRY_GUID, &self.cmdline);
        push_entry(&mut table, INITRD_ENTRY_GUID, &self.initrd);
        push_entry(&mut table, KERNEL_ENTRY_GUID, &self.kernel);
        debug_assert_eq!(table.len(), TABLE_LEN as usize);
        table.resize(PADDED_TABLE_LEN, 0);
        table
    }

    pub fn page(&self, offset_in_page: usize) -> Result<Vec<u8>> {
        let table = self.table();
        ensure!(
            offset_in_page + table.len() <= PAGE_SIZE,
            "the SEV hashes table does not fit in its page at offset {offset_in_page}"
        );
        let mut page = vec![0_u8; PAGE_SIZE];
        page[offset_in_page..offset_in_page + table.len()].copy_from_slice(&table);
        Ok(page)
    }
}

fn push_entry(table: &mut Vec<u8>, guid: &str, hash: &[u8; 32]) {
    table.extend_from_slice(&guid_le(guid));
    table.extend_from_slice(&ENTRY_LEN.to_le_bytes());
    table.extend_from_slice(hash);
}
