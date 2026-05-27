pub mod aes256;

#[cfg(target_arch = "x86_64")]
mod aes256_amd64;
#[cfg(target_arch = "aarch64")]
mod aes256_arm64;

pub use aes256::Aes256Gcm;
