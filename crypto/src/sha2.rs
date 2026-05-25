pub use crate::sha256::Sha256;
pub use crate::sha512::Sha512;

#[cfg(test)]
mod tests {
    use super::{Sha256, Sha512};
    use crate::Hasher;

    const VECTORS_SHA256: [(&str, &str); 7] = [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            "message digest",
            "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz",
            "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
        ),
    ];

    const VECTORS_SHA512: [(&str, &str); 7] = [
        (
            "",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
        (
            "a",
            "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
        ),
        (
            "abc",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        (
            "message digest",
            "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz",
            "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843",
        ),
    ];

    #[test]
    fn sha256_known_vectors_single_update() {
        for (input, expected) in VECTORS_SHA256 {
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            let digest = hasher.sum();
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn sha256_known_vectors_incremental() {
        for (input, expected) in VECTORS_SHA256 {
            let bytes = input.as_bytes();
            let mut hasher = Sha256::new();
            for chunk in bytes.chunks(3) {
                hasher.update(chunk);
            }
            let digest = hasher.sum();
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn sha512_known_vectors_single_update() {
        for (input, expected) in VECTORS_SHA512 {
            let mut hasher = Sha512::new();
            hasher.update(input.as_bytes());
            let digest = hasher.sum();
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn sha512_known_vectors_incremental() {
        for (input, expected) in VECTORS_SHA512 {
            let bytes = input.as_bytes();
            let mut hasher = Sha512::new();
            for chunk in bytes.chunks(5) {
                hasher.update(chunk);
            }
            let digest = hasher.sum();
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn sha2_block_boundary_lengths() {
        for len in [111usize, 112, 113, 127, 128, 129, 255, 256, 257] {
            let input = vec![b'a'; len];

            let mut whole_256 = Sha256::new();
            whole_256.update(&input);
            let whole_256_sum = whole_256.sum();

            let mut split_256 = Sha256::new();
            for chunk in input.chunks(7) {
                split_256.update(chunk);
            }
            let split_256_sum = split_256.sum();

            let mut whole_512 = Sha512::new();
            whole_512.update(&input);
            let whole_512_sum = whole_512.sum();

            let mut split_512 = Sha512::new();
            for chunk in input.chunks(11) {
                split_512.update(chunk);
            }
            let split_512_sum = split_512.sum();

            assert_eq!(whole_256_sum.as_ref(), split_256_sum.as_ref());
            assert_eq!(whole_512_sum.as_ref(), split_512_sum.as_ref());
        }
    }
}
