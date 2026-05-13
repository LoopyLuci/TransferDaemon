pub mod descriptor;
pub mod mmap;
pub mod doorbell;
pub mod grant;
pub mod producer;
pub mod consumer;

pub use descriptor::{VBusDmiDescriptor, ChunkMeta};
pub use mmap::MappedRegion;
pub use doorbell::Doorbell;
pub use grant::{WriteGrant, ReadGrant};
pub use producer::Producer;
pub use consumer::Consumer;
