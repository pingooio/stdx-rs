pub mod keccak;
mod sha3_256;
mod sha3_512;
mod shake256;

#[cfg(target_arch = "aarch64")]
mod keccak_arm64;

pub use sha3_256::{Sha3_256, hash_256};
pub use sha3_512::{Sha3_512, hash_512};
pub use shake256::Shake256;
