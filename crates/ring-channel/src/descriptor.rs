/// The core data structure of the DMI ring — 128 bytes, aligned to 64 bytes (two cache lines).
///
/// Using 128 bytes gives us room for the full 16-byte GCM tag and a 32-byte BLAKE3 hash
/// without any off-band side-tables, while keeping the descriptor a power-of-two in size.
///
/// Byte layout (128 bytes total):
///   [0..8)    chunk_id        u64
///   [8..16)   stream_offset   u64
///   [16..24)  gsn_start       u64
///   [24..32)  gsn_end         u64
///   [32..36)  length          u32
///   [36]      key_epoch       u8
///   [37]      flags           u8
///   [38..40)  _pad            u16
///   [40..52)  nonce           [u8; 12]   AES-GCM nonce
///   [52..68)  gcm_tag         [u8; 16]   AES-GCM authentication tag
///   [68..100) blake3_hash     [u8; 32]   full BLAKE3 plaintext hash
///   [100..128) _reserved      [u8; 28]   future use
///   TOTAL: 8+8+8+8+4+1+1+2+12+16+32+28 = 128
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct VBusDmiDescriptor {
    pub chunk_id: u64,
    pub stream_offset: u64,
    pub gsn_start: u64,
    pub gsn_end: u64,
    pub length: u32,
    pub key_epoch: u8,
    pub flags: u8,
    pub _pad: u16,
    pub nonce: [u8; 12],
    pub gcm_tag: [u8; 16],
    pub blake3_hash: [u8; 32],
    pub _reserved: [u8; 28],
}

impl Default for VBusDmiDescriptor {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl VBusDmiDescriptor {
    pub const SIZE: usize = std::mem::size_of::<VBusDmiDescriptor>();

    pub fn set_nonce_from_gsn(&mut self, gsn: u64, epoch: u8) {
        self.nonce[..8].copy_from_slice(&gsn.to_le_bytes());
        self.nonce[8] = epoch;
        self.nonce[9..].fill(0);
    }

    pub fn write_crypto_result(
        &mut self,
        nonce: &[u8; 12],
        tag: &[u8; 16],
        blake3: &[u8; 32],
    ) {
        self.nonce = *nonce;
        self.gcm_tag = *tag;
        self.blake3_hash = *blake3;
    }
}

const _: () = assert!(std::mem::size_of::<VBusDmiDescriptor>() == 128);
const _: () = assert!(std::mem::align_of::<VBusDmiDescriptor>() == 64);

/// Legacy alias kept so other modules compile without change.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChunkMeta {
    pub nonce: [u8; 12],
    pub gcm_tag: [u8; 16],
}
