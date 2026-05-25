use super::keccak::Keccak;

const CSHAKE256_RATE: usize = 136;
const CSHAKE256_DOMAIN_SEPARATOR: u8 = 0x04;
const SHAKE256_DOMAIN_SEPARATOR: u8 = 0x1f;

#[derive(Clone)]
pub struct CShake256 {
    keccak: Keccak,
}

impl CShake256 {
    #[inline]
    pub fn hash(data: &[u8], function_name: &[u8], customization: &[u8], output: &mut [u8]) {
        let mut xof = CShake256::new(function_name, customization);
        xof.write(data);
        xof.read(output);
    }

    #[inline]
    pub fn new(function_name: &[u8], customization: &[u8]) -> Self {
        if function_name.is_empty() && customization.is_empty() {
            return CShake256 {
                keccak: Keccak::new(CSHAKE256_RATE, SHAKE256_DOMAIN_SEPARATOR),
            };
        }

        let mut keccak = Keccak::new(CSHAKE256_RATE, CSHAKE256_DOMAIN_SEPARATOR);
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&encode_string(function_name));
        encoded.extend_from_slice(&encode_string(customization));
        let prefix = bytepad(&encoded, CSHAKE256_RATE);
        keccak.update(&prefix);

        return CShake256 { keccak };
    }

    #[inline]
    pub fn write(&mut self, data: &[u8]) {
        self.keccak.update(data);
    }

    #[inline]
    pub fn read(&mut self, output: &mut [u8]) {
        self.keccak.squeeze(output);
    }
}

#[inline]
pub(crate) fn left_encode(x: usize) -> Vec<u8> {
    let bytes = x.to_be_bytes();
    let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    let n = bytes.len() - first_non_zero;
    let mut out = Vec::with_capacity(1 + n);
    out.push(n as u8);
    out.extend_from_slice(&bytes[first_non_zero..]);
    return out;
}

#[inline]
pub(crate) fn right_encode(x: usize) -> Vec<u8> {
    let mut out = left_encode(x);
    let n = out[0];
    out[0] = out[1];
    for i in 1..(n as usize) {
        out[i] = out[i + 1];
    }
    out[n as usize] = n;
    return out;
}

#[inline]
pub(crate) fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut out = left_encode(s.len() * 8);
    out.extend_from_slice(s);
    return out;
}

#[inline]
pub(crate) fn bytepad(x: &[u8], w: usize) -> Vec<u8> {
    let mut out = left_encode(w);
    out.extend_from_slice(x);
    let pad_len = (w - (out.len() % w)) % w;
    out.resize(out.len() + pad_len, 0);
    return out;
}

#[cfg(test)]
mod tests {
    use super::CShake256;
    use crate::sha3::Shake256;

    const EMAIL_SIGNATURE: &[u8] = b"Email Signature";
    const SAMPLE_3_EXPECTED: &str = "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c";
    const SAMPLE_4_EXPECTED: &str = "07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb";

    #[test]
    fn cshake256_nist_sample_3() {
        let mut out = [0u8; 64];
        CShake256::hash(&[0x00, 0x01, 0x02, 0x03], b"", EMAIL_SIGNATURE, &mut out);
        assert_eq!(hex::encode(out), SAMPLE_3_EXPECTED);
    }

    #[test]
    fn cshake256_nist_sample_4() {
        let input: Vec<u8> = (0u8..200).collect();
        let mut out = [0u8; 64];
        CShake256::hash(&input, b"", EMAIL_SIGNATURE, &mut out);
        assert_eq!(hex::encode(out), SAMPLE_4_EXPECTED);
    }

    #[test]
    fn cshake256_incremental_matches_one_shot() {
        let input: Vec<u8> = (0u8..200).collect();
        let mut one_shot = [0u8; 64];
        CShake256::hash(&input, b"", EMAIL_SIGNATURE, &mut one_shot);

        let mut cshake = CShake256::new(b"", EMAIL_SIGNATURE);
        for chunk in input.chunks(9) {
            cshake.write(chunk);
        }
        let mut streamed = [0u8; 64];
        cshake.read(&mut streamed);
        assert_eq!(streamed, one_shot);
    }

    #[test]
    fn cshake256_empty_name_and_customization_matches_shake256() {
        let input = b"The quick brown fox jumps over the lazy dog";
        let mut cshake_out = [0u8; 64];
        CShake256::hash(input, b"", b"", &mut cshake_out);

        let mut shake_out = [0u8; 64];
        Shake256::hash(input, &mut shake_out);
        assert_eq!(cshake_out, shake_out);
    }
}
