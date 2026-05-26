/// Computes the Poly1305 message authentication code as specified in RFC 8439.
///
/// `key` must be 32 bytes (`r || s`).
pub fn poly1305_mac(key: &[u8], data: &[u8]) -> [u8; 16] {
    assert_eq!(key.len(), 32, "Poly1305 key must be 32 bytes");

    const MASK26: u64 = 0x3ffffff;

    let mut r_bytes = [0u8; 16];
    r_bytes.copy_from_slice(&key[..16]);

    // Clamp r per RFC 8439 section 2.5.1
    r_bytes[3] &= 15;
    r_bytes[7] &= 15;
    r_bytes[11] &= 15;
    r_bytes[15] &= 15;
    r_bytes[4] &= 252;
    r_bytes[8] &= 252;
    r_bytes[12] &= 252;

    let r = u128::from_le_bytes(r_bytes);
    let r0 = (r & MASK26 as u128) as u64;
    let r1 = ((r >> 26) & MASK26 as u128) as u64;
    let r2 = ((r >> 52) & MASK26 as u128) as u64;
    let r3 = ((r >> 78) & MASK26 as u128) as u64;
    let r4 = ((r >> 104) & MASK26 as u128) as u64;

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let mut h0 = 0u64;
    let mut h1 = 0u64;
    let mut h2 = 0u64;
    let mut h3 = 0u64;
    let mut h4 = 0u64;

    for chunk in data.chunks(16) {
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1;

        let w0 = load_u32_le_padded(&block, 0) as u64;
        let w1 = load_u32_le_padded(&block, 3) as u64;
        let w2 = load_u32_le_padded(&block, 6) as u64;
        let w3 = load_u32_le_padded(&block, 9) as u64;
        let w4 = load_u32_le_padded(&block, 12) as u64;

        let m0 = w0 & MASK26;
        let m1 = (w1 >> 2) & MASK26;
        let m2 = (w2 >> 4) & MASK26;
        let m3 = (w3 >> 6) & MASK26;
        let m4 = ((w4 >> 8) | ((block[16] as u64) << 24)) & MASK26;

        h0 += m0;
        h1 += m1;
        h2 += m2;
        h3 += m3;
        h4 += m4;

        let d0 = (h0 * r0) + (h1 * s4) + (h2 * s3) + (h3 * s2) + (h4 * s1);
        let d1 = (h0 * r1) + (h1 * r0) + (h2 * s4) + (h3 * s3) + (h4 * s2);
        let d2 = (h0 * r2) + (h1 * r1) + (h2 * r0) + (h3 * s4) + (h4 * s3);
        let d3 = (h0 * r3) + (h1 * r2) + (h2 * r1) + (h3 * r0) + (h4 * s4);
        let d4 = (h0 * r4) + (h1 * r3) + (h2 * r2) + (h3 * r1) + (h4 * r0);

        let mut c = d0 >> 26;
        h0 = d0 & MASK26;
        let d1 = d1 + c;
        c = d1 >> 26;
        h1 = d1 & MASK26;
        let d2 = d2 + c;
        c = d2 >> 26;
        h2 = d2 & MASK26;
        let d3 = d3 + c;
        c = d3 >> 26;
        h3 = d3 & MASK26;
        let d4 = d4 + c;
        c = d4 >> 26;
        h4 = d4 & MASK26;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= MASK26;
        h1 += c;
    }

    // Final carry propagation.
    let mut c = h1 >> 26;
    h1 &= MASK26;
    h2 += c;
    c = h2 >> 26;
    h2 &= MASK26;
    h3 += c;
    c = h3 >> 26;
    h3 &= MASK26;
    h4 += c;
    c = h4 >> 26;
    h4 &= MASK26;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= MASK26;
    h1 += c;

    // Compute h + -p and conditionally select the reduced value.
    let mut g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= MASK26;
    let mut g1 = h1 + c;
    c = g1 >> 26;
    g1 &= MASK26;
    let mut g2 = h2 + c;
    c = g2 >> 26;
    g2 &= MASK26;
    let mut g3 = h3 + c;
    c = g3 >> 26;
    g3 &= MASK26;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    let mask = (g4 >> 63).wrapping_sub(1);
    let not_mask = !mask;

    h0 = (h0 & not_mask) | (g0 & mask);
    h1 = (h1 & not_mask) | (g1 & mask);
    h2 = (h2 & not_mask) | (g2 & mask);
    h3 = (h3 & not_mask) | (g3 & mask);
    h4 = (h4 & not_mask) | (g4 & MASK26 & mask);

    // Serialize h and add s modulo 2^128.
    let mut f0 = (h0 | (h1 << 26)) & 0xffff_ffff;
    let mut f1 = ((h1 >> 6) | (h2 << 20)) & 0xffff_ffff;
    let mut f2 = ((h2 >> 12) | (h3 << 14)) & 0xffff_ffff;
    let mut f3 = ((h3 >> 18) | (h4 << 8)) & 0xffff_ffff;

    f0 += load_u32_le_padded(key, 16) as u64;
    c = f0 >> 32;
    f0 &= 0xffff_ffff;

    f1 += load_u32_le_padded(key, 20) as u64 + c;
    c = f1 >> 32;
    f1 &= 0xffff_ffff;

    f2 += load_u32_le_padded(key, 24) as u64 + c;
    c = f2 >> 32;
    f2 &= 0xffff_ffff;

    f3 += load_u32_le_padded(key, 28) as u64 + c;
    f3 &= 0xffff_ffff;

    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
    tag[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
    tag[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
    tag[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());
    tag
}

#[inline]
fn load_u32_le_padded(bytes: &[u8], offset: usize) -> u32 {
    let mut word = [0u8; 4];
    if offset < bytes.len() {
        let len = (bytes.len() - offset).min(4);
        word[..len].copy_from_slice(&bytes[offset..offset + len]);
    }
    u32::from_le_bytes(word)
}

#[cfg(test)]
mod tests {
    use super::poly1305_mac;

    struct TestVector {
        source: &'static str,
        key_hex: &'static str,
        data_hex: &'static str,
        expected_hex: &'static str,
    }

    const TEST_VECTORS: [TestVector; 11] = [
        // RFC 8439 section 2.5.2
        TestVector {
            source: "RFC 8439 §2.5.2",
            key_hex: "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
            data_hex: "43727970746f6772617068696320466f72756d2052657365617263682047726f7570",
            expected_hex: "a8061dc1305136c6c22b8baf0c0127a9",
        },
        // RFC 8439 appendix A.3
        TestVector {
            source: "RFC 8439 App A.3 #1",
            key_hex: "0000000000000000000000000000000000000000000000000000000000000000",
            data_hex: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            expected_hex: "00000000000000000000000000000000",
        },
        TestVector {
            source: "RFC 8439 App A.3 #2",
            key_hex: "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
            data_hex: "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
            expected_hex: "36e5f6b5c5e06070f0efca96227a863e",
        },
        TestVector {
            source: "RFC 8439 App A.3 #3",
            key_hex: "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
            data_hex: "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
            expected_hex: "f3477e7cd95417af89a6b8794c310cf0",
        },
        TestVector {
            source: "RFC 8439 App A.3 #4",
            key_hex: "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            data_hex: "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
            expected_hex: "4541669a7eaaee61e708dc7cbcc5eb62",
        },
        // BoringSSL crypto/poly1305/poly1305_tests.txt (also in RFC 8439 A.3)
        TestVector {
            source: "BoringSSL poly1305_tests #5",
            key_hex: "0200000000000000000000000000000000000000000000000000000000000000",
            data_hex: "ffffffffffffffffffffffffffffffff",
            expected_hex: "03000000000000000000000000000000",
        },
        TestVector {
            source: "BoringSSL poly1305_tests #6",
            key_hex: "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
            data_hex: "02000000000000000000000000000000",
            expected_hex: "03000000000000000000000000000000",
        },
        TestVector {
            source: "BoringSSL poly1305_tests #7",
            key_hex: "0100000000000000000000000000000000000000000000000000000000000000",
            data_hex: "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000",
            expected_hex: "05000000000000000000000000000000",
        },
        TestVector {
            source: "BoringSSL poly1305_tests #8",
            key_hex: "0100000000000000000000000000000000000000000000000000000000000000",
            data_hex: "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101",
            expected_hex: "00000000000000000000000000000000",
        },
        TestVector {
            source: "BoringSSL poly1305_tests #9",
            key_hex: "0200000000000000000000000000000000000000000000000000000000000000",
            data_hex: "fdffffffffffffffffffffffffffffff",
            expected_hex: "faffffffffffffffffffffffffffffff",
        },
        TestVector {
            source: "BoringSSL poly1305_tests #10",
            key_hex: "0100000000000000040000000000000000000000000000000000000000000000",
            data_hex: "e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000",
            expected_hex: "14000000000000005500000000000000",
        },
    ];

    fn decode_hex(input: &str) -> Vec<u8> {
        let input = input.replace(|c: char| c.is_whitespace(), "");
        assert_eq!(input.len() % 2, 0, "hex input length must be even");
        (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn poly1305_known_vectors() {
        for vector in TEST_VECTORS {
            let key = decode_hex(vector.key_hex);
            let data = decode_hex(vector.data_hex);
            let expected = decode_hex(vector.expected_hex);

            let mac = poly1305_mac(&key, &data);
            assert_eq!(mac.as_slice(), expected.as_slice(), "{}", vector.source);
        }
    }

    #[test]
    fn poly1305_chunked_equivalence() {
        let key = decode_hex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
        let data = decode_hex("2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e");
        let single = poly1305_mac(&key, &data);

        let mut rebuilt = Vec::with_capacity(data.len());
        for chunk in data.chunks(7) {
            rebuilt.extend_from_slice(chunk);
        }
        let chunked = poly1305_mac(&key, &rebuilt);
        assert_eq!(single, chunked);
    }

    #[test]
    #[should_panic(expected = "Poly1305 key must be 32 bytes")]
    fn poly1305_rejects_invalid_key_length() {
        let _ = poly1305_mac(&[0u8; 31], b"data");
    }
}
