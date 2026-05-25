use crate::{Hasher, Hmac};

/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) as defined in RFC 5869.
pub struct Hkdf<H: Hasher> {
    _phantom: core::marker::PhantomData<H>,
}

impl<H: Hasher> Hkdf<H> {
    /// Extract step: `PRK = HMAC-Hash(salt, IKM)`
    ///
    /// If `salt` is `None`, a string of `H::OUTPUT_SIZE` zero bytes is used.
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 64] {
        let default_salt = [0u8; 64];
        let salt = salt.unwrap_or(&default_salt[..H::OUTPUT_SIZE]);
        let mut mac = Hmac::<H>::new(salt);
        mac.update(ikm);
        let result = mac.finalize();
        let mut prk = [0u8; 64];
        prk[..H::OUTPUT_SIZE].copy_from_slice(result.as_ref());
        prk
    }

    /// Expand step: `OKM = T(1) || T(2) || ...` where each `T(i) = HMAC-Hash(PRK, T(i-1) || info || i)`.
    ///
    /// Returns `None` if `length > 255 * H::OUTPUT_SIZE`.
    /// `prk` must be at least `H::OUTPUT_SIZE` bytes; only the first `H::OUTPUT_SIZE` bytes are used.
    pub fn expand(prk: &[u8], info: &[u8], length: usize) -> Option<Vec<u8>> {
        let hash_len = H::OUTPUT_SIZE;
        if length == 0 {
            return Some(Vec::new());
        }
        let n = (length + hash_len - 1) / hash_len;
        if n > 255 {
            return None;
        }

        let mut okm = Vec::with_capacity(n * hash_len);
        // T(0) = empty string; we keep the previous block in a fixed-size buffer
        let mut t = [0u8; 64];
        let mut t_len = 0usize;

        for i in 1..=n {
            let mut mac = Hmac::<H>::new(&prk[..hash_len]);
            mac.update(&t[..t_len]);
            mac.update(info);
            mac.update(&[i as u8]);
            let block = mac.finalize();
            let block_bytes = block.as_ref();
            t[..hash_len].copy_from_slice(block_bytes);
            t_len = hash_len;
            okm.extend_from_slice(block_bytes);
        }

        okm.truncate(length);
        Some(okm)
    }

    /// One-shot extract-then-expand.
    ///
    /// Returns `None` if `length > 255 * H::OUTPUT_SIZE`.
    pub fn derive_key(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], length: usize) -> Option<Vec<u8>> {
        let prk = Self::extract(salt, ikm);
        Self::expand(&prk[..H::OUTPUT_SIZE], info, length)
    }
}

#[cfg(test)]
mod tests {
    use super::Hkdf;
    use crate::{Sha256, Sha512};

    struct TestVector {
        source: &'static str,
        ikm: &'static str,
        salt: Option<&'static str>,
        info: &'static str,
        length: usize,
        expected_prk: &'static str,
        expected_okm: &'static str,
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 5869 Appendix A test vectors for HKDF-SHA-256
    const SHA256_VECTORS: [TestVector; 3] = [
        // Test Case 1
        TestVector {
            source: "RFC 5869 TC1 SHA-256",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: Some("000102030405060708090a0b0c"),
            info: "f0f1f2f3f4f5f6f7f8f9",
            length: 42,
            expected_prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            expected_okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        },
        // Test Case 2
        TestVector {
            source: "RFC 5869 TC2 SHA-256",
            ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                   202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
                   404142434445464748494a4b4c4d4e4f",
            salt: Some(
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
                 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            ),
            info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                   d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                   f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            length: 82,
            expected_prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            expected_okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        },
        // Test Case 3 (no salt, no info)
        TestVector {
            source: "RFC 5869 TC3 SHA-256 (no salt, no info)",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: None,
            info: "",
            length: 42,
            expected_prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            expected_okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        },
    ];

    // HKDF-SHA-512 vectors computed from the RFC 5869 test-case inputs
    // (verified with Python's hashlib: hmac.new / same algorithm, SHA-512 substituted)
    const SHA512_VECTORS: [TestVector; 3] = [
        // TC1 inputs, SHA-512
        TestVector {
            source: "TC1 SHA-512",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: Some("000102030405060708090a0b0c"),
            info: "f0f1f2f3f4f5f6f7f8f9",
            length: 42,
            expected_prk: "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
            expected_okm: "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
        },
        // TC2 inputs, SHA-512
        TestVector {
            source: "TC2 SHA-512",
            ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                   202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
                   404142434445464748494a4b4c4d4e4f",
            salt: Some(
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
                 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            ),
            info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                   d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                   f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            length: 82,
            expected_prk: "35672542907d4e142c00e84499e74e1de08be86535f924e022804ad775dde27ec86cd1e5b7d178c74489bdbeb30712beb82d4f97416c5a94ea81ebdf3e629e4a",
            expected_okm: "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a93",
        },
        // TC3 inputs, SHA-512 (no salt, no info)
        TestVector {
            source: "TC3 SHA-512 (no salt, no info)",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: None,
            info: "",
            length: 42,
            expected_prk: "fd200c4987ac491313bd4a2a13287121247239e11c9ef82802044b66ef357e5b194498d0682611382348572a7b1611de54764094286320578a863f36562b0df6",
            expected_okm: "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac",
        },
    ];

    #[test]
    fn hkdf_sha256_vectors() {
        for v in &SHA256_VECTORS {
            let ikm = hex_decode(v.ikm.replace(|c: char| c.is_whitespace(), "").as_str());
            let salt = v.salt.map(|s| hex_decode(s.replace(|c: char| c.is_whitespace(), "").as_str()));
            let info = hex_decode(v.info.replace(|c: char| c.is_whitespace(), "").as_str());
            let expected_prk = hex_decode(v.expected_prk);
            let expected_okm = hex_decode(v.expected_okm);

            let prk = Hkdf::<Sha256>::extract(salt.as_deref(), &ikm);
            assert_eq!(&prk[..32], expected_prk.as_slice(), "{} PRK", v.source);

            let okm = Hkdf::<Sha256>::expand(&prk[..32], &info, v.length)
                .expect("expand should not fail");
            assert_eq!(okm, expected_okm, "{} OKM", v.source);

            let okm2 = Hkdf::<Sha256>::derive_key(salt.as_deref(), &ikm, &info, v.length)
                .expect("derive_key should not fail");
            assert_eq!(okm2, expected_okm, "{} derive_key OKM", v.source);
        }
    }

    #[test]
    fn hkdf_sha512_vectors() {
        for v in &SHA512_VECTORS {
            let ikm = hex_decode(v.ikm.replace(|c: char| c.is_whitespace(), "").as_str());
            let salt = v.salt.map(|s| hex_decode(s.replace(|c: char| c.is_whitespace(), "").as_str()));
            let info = hex_decode(v.info.replace(|c: char| c.is_whitespace(), "").as_str());
            let expected_prk = hex_decode(v.expected_prk);
            let expected_okm = hex_decode(v.expected_okm);

            let prk = Hkdf::<Sha512>::extract(salt.as_deref(), &ikm);
            assert_eq!(&prk[..64], expected_prk.as_slice(), "{} PRK", v.source);

            let okm = Hkdf::<Sha512>::expand(&prk[..64], &info, v.length)
                .expect("expand should not fail");
            assert_eq!(okm, expected_okm, "{} OKM", v.source);

            let okm2 = Hkdf::<Sha512>::derive_key(salt.as_deref(), &ikm, &info, v.length)
                .expect("derive_key should not fail");
            assert_eq!(okm2, expected_okm, "{} derive_key OKM", v.source);
        }
    }

    #[test]
    fn hkdf_expand_length_limit() {
        let prk = [0u8; 32];
        // max allowed for SHA-256: 255 * 32 = 8160
        assert!(Hkdf::<Sha256>::expand(&prk, b"", 8160).is_some());
        assert!(Hkdf::<Sha256>::expand(&prk, b"", 8161).is_none());
        assert!(Hkdf::<Sha256>::expand(&prk, b"", 0).is_some());
    }
}
