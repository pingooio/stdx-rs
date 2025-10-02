use crate::{Uuid, Version};

impl Uuid {
    /// Create a new version 7 UUID using a time value and random bytes.
    ///
    /// When the `std` feature is enabled, you can also use [`Uuid::now_v7`].
    ///
    /// Note that usage of this method requires the `v7` feature of this crate
    /// to be enabled.
    ///
    /// # References
    ///
    /// * [Version 7 UUIDs in Draft RFC: New UUID Formats, Version 4](https://datatracker.ietf.org/doc/html/draft-peabody-dispatch-new-uuid-format-04#section-5.2)
    pub fn new_v7() -> Uuid {
        let now = std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .expect("Getting elapsed time since UNIX_EPOCH. If this fails, we've somehow violated causality");

        // let now = (now.as_secs(), now.subsec_nanos());
        return Self::new_v7_with_timestamp(now.as_millis() as u64);
    }

    pub fn new_v7_with_timestamp(unix_millis: u64) -> Self {
        /*
            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                           unix_ts_ms                          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          unix_ts_ms           |  ver  |  rand_a (12 bit seq)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |var|                        rand_b                             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            rand_b                             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            unix_ts_ms:
                48 bit big-endian unsigned number of Unix epoch timestamp as per Section 6.1.
            ver:
                4 bit UUIDv7 version set as per Section 4
            rand_a:
                12 bits pseudo-random data to provide uniqueness as per Section 6.2 and Section 6.6.
            var:
                The 2 bit variant defined by Section 4.
            rand_b:
                The final 62 bits of pseudo-random data to provide uniqueness as per Section 6.2 and Section 6.6.
        */

        // // unix_high
        // let unix_high = ((millis >> 16) & 0xFFFF_FFFF) as u32;
        // // unix_low
        // let unix_low = (millis & 0xFFFF) as u16;

        // let unix_millis =
        //     (unix_seconds * 1000).saturating_add(nanoseconds.unwrap_or_default() as u64 / 1_000_000);
        let mut uuid = Uuid(rand::random());

        // let random_bytes: [u8; 10] = rand::random();
        // random_and_version
        // let d3: u16 =
        //     (uuid.0[7] as u16 | ((uuid.0[6] as u16) << 8) & 0x0FFF) | (0x7 << 12);

        uuid.0[0] = (unix_millis >> 40) as u8;
        uuid.0[1] = (unix_millis >> 32) as u8;
        uuid.0[2] = (unix_millis >> 24) as u8;
        uuid.0[3] = (unix_millis >> 16) as u8;
        uuid.0[4] = (unix_millis >> 8) as u8;
        uuid.0[5] = unix_millis as u8;

        // Version: 7. 7 << 4 = 0x70
        uuid.0[6] = (uuid.0[6] & 0x0f) | ((Version::V7 as u8) << 4);
        // Variant: RFC4122
        uuid.0[8] = (uuid.0[8] & 0x3F) | 0x80;

        // uuid[6] = 0x70 | (0x0F & byte(s>>8))
        // uuid[7] = byte(s)
        // uuid.0[6] = (d3 >> 8) as u8;
        // uuid.0[7] = d3 as u8;

        return uuid;
    }
}
