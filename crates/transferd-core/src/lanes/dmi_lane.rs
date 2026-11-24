use crate::transport::{Chunk, LaneMetrics, TransportError, TransportLane};
use async_trait::async_trait;
use ring_channel::Producer;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::Mutex;
use transferd_crypto::{DmiEncryptor, EncryptResult};

pub struct DmiSenderLane {
    id: u32,
    producer: Mutex<Producer>,
    encryptor: Mutex<DmiEncryptor>,
    metrics: Arc<LaneMetrics>,
    descriptor_count: usize,
}

impl DmiSenderLane {
    pub fn new(id: u32, producer: Producer, descriptor_count: usize, key: &[u8; 32]) -> Self {
        let metrics = Arc::new(LaneMetrics::default());
        metrics.bandwidth_bps.store(100_000_000_000, Ordering::SeqCst);
        metrics.rtt_ms.store(1_000, Ordering::SeqCst);
        Self {
            id,
            producer: Mutex::new(producer),
            encryptor: Mutex::new(DmiEncryptor::new(key)),
            metrics,
            descriptor_count,
        }
    }
}

#[async_trait]
impl TransportLane for DmiSenderLane {
    fn id(&self) -> u32 { self.id }
    fn metrics(&self) -> Arc<LaneMetrics> { self.metrics.clone() }
    fn capacity(&self) -> usize { self.descriptor_count }

    async fn send(&self, chunk: Chunk) -> Result<(), TransportError> {
        let len = chunk.payload.len();
        if len == 0 { return Ok(()); }

        let mut producer = self.producer.lock().await;
        let grant = producer.reserve_grant(len).await.map_err(|_| TransportError::Saturated)?;

        // Encrypt plaintext directly into the DMI grant buffer.
        let result: EncryptResult = {
            let mut encryptor = self.encryptor.lock().await;
            // Build AAD from the GSN range (4 bytes each side) so the tag covers routing metadata.
            let mut aad = [0u8; 16];
            aad[..8].copy_from_slice(&chunk.gsn.0.to_le_bytes());
            aad[8..16].copy_from_slice(&(chunk.gsn.0 + len as u64).to_le_bytes());

            let dst = unsafe { std::slice::from_raw_parts_mut(grant.ptr, len) };
            unsafe {
                encryptor.encrypt_fused(
                    &chunk.payload,
                    dst,
                    chunk.gsn.0,
                    chunk.key_epoch,
                    &aad,
                )
            }
        };

        producer.commit_grant(
            grant,
            chunk.gsn.0,
            chunk.gsn.0 + len as u64,
            &result.nonce,
            &result.gcm_tag,
            &result.blake3_hash,
            chunk.key_epoch,
        );
        Ok(())
    }

    async fn recv(&mut self) -> Option<Result<Chunk, TransportError>> { None }
    fn is_alive(&self) -> bool { true }
}
