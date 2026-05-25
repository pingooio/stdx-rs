mod keccak;
mod sha3_256;
mod sha3_512;
mod shake256;

pub use sha3_256::{Sha3_256, hash_256};
pub use sha3_512::{Sha3_512, hash_512};
pub use shake256::Shake256;

#[cfg(test)]
mod tests {
    use super::{Sha3_256, Sha3_512, Shake256, hash_256, hash_512};

    fn vectors_sha3() -> Vec<(Vec<u8>, &'static str, &'static str)> {
        vec![
            (
                b"".to_vec(),
                "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
            ),
            (
                b"abc".to_vec(),
                "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
            ),
            (
                b"hello world".to_vec(),
                "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938",
                "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a",
            ),
            (
                b"The quick brown fox jumps over the lazy dog".to_vec(),
                "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
                "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450",
            ),
            (
                b"The quick brown fox jumps over the lazy dog.".to_vec(),
                "a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d",
                "18f4f4bd419603f95538837003d9d254c26c23765565162247483f65c50303597bc9ce4d289f21d1c2f1f458828e33dc442100331b35e7eb031b5d38ba6460f8",
            ),
            (
                vec![b'a'; 1_000_000],
                "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1",
                "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87",
            ),
        ]
    }

    fn vectors_shake256() -> Vec<(Vec<u8>, usize, &'static str)> {
        vec![
            (
                b"".to_vec(),
                64,
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
            ),
            (
                b"".to_vec(),
                128,
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86",
            ),
            (
                b"abc".to_vec(),
                64,
                "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
            ),
            (
                b"hello world".to_vec(),
                64,
                "369771bb2cb9d2b04c1d54cca487e372d9f187f73f7ba3f65b95c8ee7798c527f4f3c2d55c2d46a29f2e945d469c3df27853a8735271f5cc2d9e889544357116",
            ),
            (
                b"The quick brown fox jumps over the lazy dog".to_vec(),
                64,
                "2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca1d01d1369a23539cd80f7c054b6e5daf9c962cad5b8ed5bd11998b40d5734442",
            ),
            (
                b"The quick brown fox jumps over the lazy dog.".to_vec(),
                64,
                "bd225bfc8b255f3036f0c8866010ed0053b5163a3cae111e723c0c8e704eca4e5d0f1e2a2fa18c8a219de6b88d5917ff5dd75b5fb345e7409a3b333b508a65fb",
            ),
            (
                vec![b'a'; 1_000_000],
                64,
                "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a3fd124d4df76c0a539ee7dd2f6e1ec346124c815d9410e145eb561bcd97b18ab",
            ),
        ]
    }

    #[test]
    fn sha3_known_vectors_single_update() {
        for (input, expected_256, expected_512) in vectors_sha3() {
            assert_eq!(hex::encode(hash_256(&input)), expected_256);
            assert_eq!(hex::encode(hash_512(&input)), expected_512);
        }
    }

    #[test]
    fn sha3_known_vectors_incremental() {
        for (input, expected_256, expected_512) in vectors_sha3() {
            let mut sha3_256 = Sha3_256::new();
            for chunk in input.chunks(7) {
                sha3_256.write(chunk);
            }
            assert_eq!(hex::encode(sha3_256.sum()), expected_256);

            let mut sha3_512 = Sha3_512::new();
            for chunk in input.chunks(11) {
                sha3_512.write(chunk);
            }
            assert_eq!(hex::encode(sha3_512.sum()), expected_512);
        }
    }

    #[test]
    fn shake256_known_vectors() {
        for (input, output_len, expected) in vectors_shake256() {
            let mut output = vec![0u8; output_len];
            Shake256::hash(&input, &mut output);
            assert_eq!(hex::encode(output), expected);
        }
    }

    #[test]
    fn shake256_incremental_and_streaming_read() {
        let mut one_shot = vec![0u8; 128];
        Shake256::hash(b"", &mut one_shot);

        let mut shake = Shake256::new();
        shake.write(b"");
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        shake.read(&mut first);
        shake.read(&mut second);

        let mut combined = vec![0u8; 128];
        combined[..64].copy_from_slice(&first);
        combined[64..].copy_from_slice(&second);

        assert_eq!(combined, one_shot);
    }
}
