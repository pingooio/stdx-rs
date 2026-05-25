use super::cshake::{CShake256, bytepad, encode_string, right_encode};

const KMAC256_RATE: usize = 136;

#[derive(Clone)]
pub struct Kmac256 {
    cshake: CShake256,
}

impl Kmac256 {
    #[inline]
    pub fn mac(key: &[u8], data: &[u8], customization: &[u8], output: &mut [u8]) {
        let mut kmac = Kmac256::new(key, customization);
        kmac.update(data);
        kmac.finalize_into(output);
    }

    #[inline]
    pub fn new(key: &[u8], customization: &[u8]) -> Self {
        let mut cshake = CShake256::new(b"KMAC", customization);
        let key_padded = bytepad(&encode_string(key), KMAC256_RATE);
        cshake.write(&key_padded);
        return Kmac256 { cshake };
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.cshake.write(data);
    }

    #[inline]
    pub fn finalize_into(mut self, output: &mut [u8]) {
        let output_bits = output
            .len()
            .checked_mul(8)
            .expect("output size too large for KMAC");
        let encoded_output_len = right_encode(output_bits);
        self.cshake.write(&encoded_output_len);
        self.cshake.read(output);
    }
}

#[cfg(test)]
mod tests {
    use super::Kmac256;

    const KEY: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
        0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
        0x5C, 0x5D, 0x5E, 0x5F,
    ];
    const TAGGED_APP: &[u8] = b"My Tagged Application";

    // NIST SP 800-185 KMAC_samples.pdf sample #4
    const KMAC256_SAMPLE_4: &str = "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd";
    // NIST SP 800-185 KMAC_samples.pdf sample #5
    const KMAC256_SAMPLE_5: &str = "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69";
    // NIST SP 800-185 KMAC_samples.pdf sample #6 (streaming-friendly)
    const KMAC256_SAMPLE_6: &str = "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965";

    #[test]
    fn kmac256_nist_sample_4() {
        let mut out = [0u8; 64];
        Kmac256::mac(&KEY, &[0x00, 0x01, 0x02, 0x03], TAGGED_APP, &mut out);
        assert_eq!(hex::encode(out), KMAC256_SAMPLE_4);
    }

    #[test]
    fn kmac256_nist_sample_5() {
        let input: Vec<u8> = (0u8..200).collect();
        let mut out = [0u8; 64];
        Kmac256::mac(&KEY, &input, b"", &mut out);
        assert_eq!(hex::encode(out), KMAC256_SAMPLE_5);
    }

    #[test]
    fn kmac256_nist_sample_6_incremental() {
        let input: Vec<u8> = (0u8..200).collect();
        let mut kmac = Kmac256::new(&KEY, TAGGED_APP);
        for chunk in input.chunks(1) {
            kmac.update(chunk);
        }
        let mut out = [0u8; 64];
        kmac.finalize_into(&mut out);
        assert_eq!(hex::encode(out), KMAC256_SAMPLE_6);
    }

    #[test]
    fn kmac256_incremental_matches_one_shot() {
        let input: Vec<u8> = (0u8..200).collect();

        let mut one_shot = [0u8; 64];
        Kmac256::mac(&KEY, &input, TAGGED_APP, &mut one_shot);

        let mut kmac = Kmac256::new(&KEY, TAGGED_APP);
        for chunk in input.chunks(7) {
            kmac.update(chunk);
        }
        let mut incremental = [0u8; 64];
        kmac.finalize_into(&mut incremental);
        assert_eq!(incremental, one_shot);
    }
}
