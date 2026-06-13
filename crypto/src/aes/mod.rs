mod aes;
mod aes_ctr;
mod aes_gcm;
mod ghash;

#[cfg(target_arch = "x86_64")]
mod aes_amd64;
#[cfg(target_arch = "aarch64")]
mod aes_arm64;

#[cfg(target_arch = "x86_64")]
mod aes_gcm_amd64;
#[cfg(target_arch = "aarch64")]
mod aes_gcm_arm64;

#[cfg(target_arch = "x86_64")]
mod aes_ctr_amd64;
#[cfg(target_arch = "aarch64")]
mod aes_ctr_arm64;

#[cfg(target_arch = "x86_64")]
mod ghash_amd64;
#[cfg(target_arch = "aarch64")]
mod ghash_arm64;

pub use aes_ctr::Aes256Ctr;
pub use aes_gcm::Aes256Gcm;
