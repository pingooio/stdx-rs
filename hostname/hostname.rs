use std::ffi::OsString;

// make it compatible with the [hostname](https://crates.io/crates/hostname) crate
pub fn get() -> Result<OsString, std::io::Error> {
    return Ok(net::hostname());
}
