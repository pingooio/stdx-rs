use crate::{Hasher, Hmac};

/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) as defined in RFC 5869.
pub struct Hkdf<H: Hasher> {
    _phantom: core::marker::PhantomData<H>,
}

impl<H: Hasher> Hkdf<H> {
    /// Extract step: `PRK = HMAC-Hash(salt, IKM)`.
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

    /// Expand step: `OKM = T(1) || T(2) || ...`, where
    /// `T(i) = HMAC-Hash(PRK, T(i-1) || info || i)`.
    ///
    /// # Panics
    ///
    /// Panics if `N > 255 * H::OUTPUT_SIZE` or if `prk.len() < H::OUTPUT_SIZE`.
    pub fn expand<const N: usize>(prk: &[u8], info: &[u8]) -> [u8; N] {
        assert!(
            prk.len() >= H::OUTPUT_SIZE,
            "HKDF PRK must be at least {} bytes",
            H::OUTPUT_SIZE
        );
        assert!(N <= 255 * H::OUTPUT_SIZE, "HKDF output length exceeds RFC 5869 limit");

        let mut okm = [0u8; N];
        if N == 0 {
            return okm;
        }

        let mut t = [0u8; 64];
        let mut t_len = 0usize;
        let mut offset = 0usize;
        let mut counter = 1u8;

        while offset < N {
            let mut mac = Hmac::<H>::new(&prk[..H::OUTPUT_SIZE]);
            mac.update(&t[..t_len]);
            mac.update(info);
            mac.update(&[counter]);
            let block = mac.finalize();
            let block_bytes = block.as_ref();
            let chunk_len = (N - offset).min(H::OUTPUT_SIZE);
            okm[offset..offset + chunk_len].copy_from_slice(&block_bytes[..chunk_len]);
            t[..H::OUTPUT_SIZE].copy_from_slice(block_bytes);
            t_len = H::OUTPUT_SIZE;
            offset += chunk_len;
            counter = counter.wrapping_add(1);
        }

        okm
    }

    /// One-shot extract-then-expand.
    ///
    /// # Panics
    ///
    /// Panics if `N > 255 * H::OUTPUT_SIZE`.
    pub fn derive_key<const N: usize>(ikm: &[u8], info: &[u8], salt: Option<&[u8]>) -> [u8; N] {
        let prk = Self::extract(salt, ikm);
        Self::expand::<N>(&prk[..H::OUTPUT_SIZE], info)
    }
}

#[cfg(test)]
mod tests {
    use super::Hkdf;
    use crate::{Sha256, Sha512};

    struct TestVector {
        ikm: &'static str,
        salt: Option<&'static str>,
        info: &'static str,
        expected_prk: &'static str,
        expected_okm: &'static str,
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        let input = input.replace(|c: char| c.is_whitespace(), "");
        (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
            .collect()
    }

    const SHA256_VECTORS: [TestVector; 4] = [
        TestVector {
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: Some("000102030405060708090a0b0c"),
            info: "f0f1f2f3f4f5f6f7f8f9",
            expected_prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            expected_okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        },
        TestVector {
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
            expected_prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            expected_okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        },
        TestVector {
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: Some(""),
            info: "",
            expected_prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            expected_okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        },
        TestVector {
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: None,
            info: "",
            expected_prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            expected_okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        },
    ];

    const SHA512_VECTORS: [TestVector; 4] = [
        TestVector {
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: Some("000102030405060708090a0b0c"),
            info: "f0f1f2f3f4f5f6f7f8f9",
            expected_prk: "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
            expected_okm: "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
        },
        TestVector {
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
            expected_prk: "35672542907d4e142c00e84499e74e1de08be86535f924e022804ad775dde27ec86cd1e5b7d178c74489bdbeb30712beb82d4f97416c5a94ea81ebdf3e629e4a",
            expected_okm: "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a93",
        },
        TestVector {
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: Some(""),
            info: "",
            expected_prk: "fd200c4987ac491313bd4a2a13287121247239e11c9ef82802044b66ef357e5b194498d0682611382348572a7b1611de54764094286320578a863f36562b0df6",
            expected_okm: "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac",
        },
        TestVector {
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: None,
            info: "",
            expected_prk: "fd200c4987ac491313bd4a2a13287121247239e11c9ef82802044b66ef357e5b194498d0682611382348572a7b1611de54764094286320578a863f36562b0df6",
            expected_okm: "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac",
        },
    ];

    #[test]
    fn hkdf_sha256_vectors() {
        for (i, vector) in SHA256_VECTORS.iter().enumerate() {
            let ikm = decode_hex(vector.ikm);
            let salt = vector.salt.map(decode_hex);
            let info = decode_hex(vector.info);
            let expected_prk = decode_hex(vector.expected_prk);
            let expected_okm = decode_hex(vector.expected_okm);

            let prk = Hkdf::<Sha256>::extract(salt.as_deref(), &ikm);
            assert_eq!(&prk[..32], expected_prk.as_slice(), "vector {} PRK", i);

            let okm = match expected_okm.len() {
                42 => Hkdf::<Sha256>::expand::<42>(&prk[..32], &info).to_vec(),
                82 => Hkdf::<Sha256>::expand::<82>(&prk[..32], &info).to_vec(),
                _ => unreachable!(),
            };
            assert_eq!(okm, expected_okm, "vector {} OKM", i);

            let derived = match expected_okm.len() {
                42 => Hkdf::<Sha256>::derive_key::<42>(&ikm, &info, salt.as_deref()).to_vec(),
                82 => Hkdf::<Sha256>::derive_key::<82>(&ikm, &info, salt.as_deref()).to_vec(),
                _ => unreachable!(),
            };
            assert_eq!(derived, expected_okm, "vector {} derive_key OKM", i);
        }
    }

    #[test]
    fn hkdf_sha512_vectors() {
        for (i, vector) in SHA512_VECTORS.iter().enumerate() {
            let ikm = decode_hex(vector.ikm);
            let salt = vector.salt.map(decode_hex);
            let info = decode_hex(vector.info);
            let expected_prk = decode_hex(vector.expected_prk);
            let expected_okm = decode_hex(vector.expected_okm);

            let prk = Hkdf::<Sha512>::extract(salt.as_deref(), &ikm);
            assert_eq!(&prk[..64], expected_prk.as_slice(), "vector {} PRK", i);

            let okm = match expected_okm.len() {
                42 => Hkdf::<Sha512>::expand::<42>(&prk[..64], &info).to_vec(),
                82 => Hkdf::<Sha512>::expand::<82>(&prk[..64], &info).to_vec(),
                _ => unreachable!(),
            };
            assert_eq!(okm, expected_okm, "vector {} OKM", i);

            let derived = match expected_okm.len() {
                42 => Hkdf::<Sha512>::derive_key::<42>(&ikm, &info, salt.as_deref()).to_vec(),
                82 => Hkdf::<Sha512>::derive_key::<82>(&ikm, &info, salt.as_deref()).to_vec(),
                _ => unreachable!(),
            };
            assert_eq!(derived, expected_okm, "vector {} derive_key OKM", i);
        }
    }

    #[test]
    fn hkdf_zero_length_output() {
        let prk = [0u8; 32];
        assert_eq!(Hkdf::<Sha256>::expand::<0>(&prk, b""), []);
        assert_eq!(Hkdf::<Sha256>::derive_key::<0>(b"ikm", b"info", None), []);
    }

    #[test]
    #[should_panic(expected = "HKDF output length exceeds RFC 5869 limit")]
    fn hkdf_expand_panics_when_output_is_too_large() {
        let prk = [0u8; 32];
        let _ = Hkdf::<Sha256>::expand::<8161>(&prk, b"");
    }

    #[test]
    #[should_panic(expected = "HKDF PRK must be at least 32 bytes")]
    fn hkdf_expand_panics_when_prk_is_too_short() {
        let _ = Hkdf::<Sha256>::expand::<32>(&[0u8; 31], b"");
    }
}
