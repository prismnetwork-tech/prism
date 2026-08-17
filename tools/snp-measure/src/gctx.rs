use sha2::{Digest, Sha384};

pub const DIGEST_SIZE: usize = 48;
pub const PAGE_SIZE: usize = 4096;

/// SNP records the VMSA page in the RMP at GPA (u64)(-1), page aligned with
/// everything above bit 51 cleared.
const VMSA_GPA: u64 = 0xFFFF_FFFF_F000;

/// Size of PAGE_INFO, and the value the structure carries in its own LENGTH
/// field. SNP ABI 8.17.2, table 67.
const PAGE_INFO_LEN: u16 = 0x70;

#[derive(Clone, Copy)]
enum PageType {
    Normal = 0x01,
    Vmsa = 0x02,
    Zero = 0x03,
    Secrets = 0x05,
    Cpuid = 0x06,
}

/// The launch digest the PSP builds while it imports the initial guest image.
/// Every measured page folds its own type and guest physical address into the
/// running digest, so moving a page or changing what a page is for produces a
/// different measurement even when the bytes are identical.
pub struct LaunchDigest([u8; DIGEST_SIZE]);

impl LaunchDigest {
    pub fn new() -> Self {
        Self([0_u8; DIGEST_SIZE])
    }

    pub fn finish(self) -> [u8; DIGEST_SIZE] {
        self.0
    }

    fn update(&mut self, page_type: PageType, gpa: u64, contents: &[u8; DIGEST_SIZE]) {
        let mut page_info = Vec::with_capacity(PAGE_INFO_LEN as usize);
        page_info.extend_from_slice(&self.0);
        page_info.extend_from_slice(contents);
        page_info.extend_from_slice(&PAGE_INFO_LEN.to_le_bytes());
        page_info.push(page_type as u8);
        page_info.push(0); // IMI_PAGE
        page_info.extend_from_slice(&[0, 0, 0, 0]); // VMPL3, VMPL2, VMPL1 permissions, reserved
        page_info.extend_from_slice(&gpa.to_le_bytes());
        debug_assert_eq!(page_info.len(), PAGE_INFO_LEN as usize);

        self.0 = sha384(&page_info);
    }

    pub fn normal_pages(&mut self, start_gpa: u64, data: &[u8]) {
        assert!(
            data.len().is_multiple_of(PAGE_SIZE),
            "measured region is not page aligned"
        );
        for (index, page) in data.chunks_exact(PAGE_SIZE).enumerate() {
            let gpa = start_gpa + (index * PAGE_SIZE) as u64;
            self.update(PageType::Normal, gpa, &sha384(page));
        }
    }

    pub fn vmsa_page(&mut self, page: &[u8; PAGE_SIZE]) {
        self.update(PageType::Vmsa, VMSA_GPA, &sha384(page));
    }

    pub fn zero_pages(&mut self, gpa: u64, length: u64) {
        self.span(PageType::Zero, gpa, length);
    }

    pub fn secrets_page(&mut self, gpa: u64) {
        self.update(PageType::Secrets, gpa, &[0_u8; DIGEST_SIZE]);
    }

    pub fn cpuid_page(&mut self, gpa: u64) {
        self.update(PageType::Cpuid, gpa, &[0_u8; DIGEST_SIZE]);
    }

    fn span(&mut self, page_type: PageType, gpa: u64, length: u64) {
        assert!(
            length.is_multiple_of(PAGE_SIZE as u64),
            "region is not page aligned"
        );
        let mut offset = 0;
        while offset < length {
            self.update(page_type, gpa + offset, &[0_u8; DIGEST_SIZE]);
            offset += PAGE_SIZE as u64;
        }
    }
}

pub fn sha384(data: &[u8]) -> [u8; DIGEST_SIZE] {
    Sha384::digest(data).into()
}
