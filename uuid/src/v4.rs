use crate::Uuid;

impl Uuid {
    pub fn new_v4() -> Uuid {
        return Uuid::from_u128(rand::random::<u128>() & 0xFFFFFFFFFFFF4FFFBFFFFFFFFFFFFFFF | 0x40008000000000000000);
        // let mut uuid = Uuid(rand::random());

        // // Version: V4. 4 << 4 = 0x40
        // uuid.0[6] = (uuid.0[6] & 0x0f) | ((Version::V4 as u8) << 4);
        // // Variant: RFC4122
        // uuid.0[8] = (uuid.0[8] & 0x3f) | 0x80;

        // return uuid;
    }
}
