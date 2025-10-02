use crate::{Uuid, Version};

impl Uuid {
    pub fn new_v8(buf: [u8; 16]) -> Uuid {
        let mut uuid = Uuid::from_bytes(buf);
        // Version: 8
        uuid.0[6] = (uuid.0[6] & 0x0f) | ((Version::V8 as u8) << 4);
        // Variant: RFC4122
        uuid.0[8] = (uuid.0[8] & 0x3F) | 0x80;
        return uuid;
    }
}
