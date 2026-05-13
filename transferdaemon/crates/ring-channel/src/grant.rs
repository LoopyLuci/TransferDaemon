use crate::descriptor::VBusDmiDescriptor;

/// A writable region grant — owns a raw pointer into the DMI data buffer.
/// The caller must commit or drop before the next reserve_grant call.
pub struct WriteGrant {
    /// Raw pointer to the start of the writable slice in the data area.
    pub ptr: *mut u8,
    pub len: usize,
    pub slot_idx: usize,
}

// Safety: WriteGrant is only created inside Producer::reserve_grant which enforces
// exclusive access via the producer index protocol.
unsafe impl Send for WriteGrant {}

impl WriteGrant {
    /// Returns a mutable slice for the caller to fill.
    ///
    /// # Safety
    /// Must not outlive the underlying MappedRegion.
    pub unsafe fn as_slice_mut(&mut self) -> &mut [u8] {
        std::slice::from_raw_parts_mut(self.ptr, self.len)
    }
}

/// A readable region of the DMI data buffer, obtained by the consumer.
pub struct ReadGrant<'a> {
    pub buf: &'a [u8],
    pub slot_idx: usize,
    pub desc: &'a VBusDmiDescriptor,
}
