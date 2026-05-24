use lz4::{Error, compress, compress_to_buffer, decompress, decompress_to_buffer};
use lz4_reference::block as lz4_block;

fn deterministic_bytes(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    let mut out = vec![0u8; len];
    for byte in &mut out {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *byte = (state & 0xFF) as u8;
    }
    out
}

fn test_inputs() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0],
        vec![1, 2, 3],
        vec![7; 4],
        vec![9; 32],
        (0..256).map(|x| x as u8).collect(),
        deterministic_bytes(17, 1),
        deterministic_bytes(129, 2),
        deterministic_bytes(4096, 3),
        b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(100),
        {
            let mut data = Vec::new();
            for i in 0..4096 {
                data.push((i % 23) as u8);
            }
            data
        },
    ]
}

fn interop_stress_inputs() -> Vec<Vec<u8>> {
    let mut cases = test_inputs();

    for len in [5usize, 6, 7, 8, 12, 13, 14, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 4095, 4096, 4097, 65_535] {
        cases.push(deterministic_bytes(len, 0xC0FFEE_u32 ^ len as u32));
    }

    for len in 0usize..=512 {
        let mut repeating = vec![0u8; len];
        for (i, byte) in repeating.iter_mut().enumerate() {
            *byte = (i % 7) as u8;
        }
        cases.push(repeating);
    }

    cases
}

fn max_compressed_size(source_len: usize) -> usize {
    source_len + (source_len / 255) + 16
}

#[test]
fn roundtrip_allocating_api() {
    for input in test_inputs() {
        let compressed = compress(&input).unwrap();
        let decompressed = decompress(&compressed, input.len()).unwrap();
        assert_eq!(decompressed, input);
    }
}

#[test]
fn roundtrip_buffer_api() {
    for input in test_inputs() {
        let mut compressed = vec![0u8; input.len() + (input.len() / 255) + 16];
        let written = compress_to_buffer(&input, &mut compressed).unwrap();
        compressed.truncate(written);

        let mut output = vec![0u8; input.len()];
        let out_written = decompress_to_buffer(&compressed, &mut output).unwrap();
        output.truncate(out_written);
        assert_eq!(output, input);
    }
}

#[test]
fn compress_to_buffer_reports_small_destination() {
    let input = deterministic_bytes(1024, 7);
    let mut destination = vec![0u8; 8];
    let error = compress_to_buffer(&input, &mut destination).unwrap_err();
    assert_eq!(error, Error::DestinationTooSmall);
}

#[test]
fn decompress_respects_capacity() {
    let input = b"abcd".repeat(1024);
    let compressed = compress(&input).unwrap();
    let error = decompress(&compressed, input.len() - 1).unwrap_err();
    assert_eq!(error, Error::DestinationTooSmall);
}

#[test]
fn decompress_to_buffer_detects_corruption() {
    let malformed_cases = [
        vec![0x00, 0x01],       // offset bytes missing
        vec![0x20, 0xAA],       // literal length longer than source
        vec![0x00, 0x00, 0x00], // invalid zero offset
        vec![0xF0],             // literal extension missing
    ];

    for case in malformed_cases {
        let mut output = vec![0u8; 64];
        let error = decompress_to_buffer(&case, &mut output).unwrap_err();
        assert_eq!(error, Error::CorruptData);
    }
}

#[test]
fn interoperates_with_lz4_crate() {
    for input in test_inputs() {
        let reference_compressed = lz4_block::compress(&input, None, false).unwrap();
        let ours = decompress(&reference_compressed, input.len()).unwrap();
        assert_eq!(ours, input);

        let our_compressed = compress(&input).unwrap();
        let reference_decompressed = lz4_block::decompress(&our_compressed, Some(input.len() as i32)).unwrap();
        assert_eq!(reference_decompressed, input);
    }
}

#[test]
fn interop_large_repetitive_stream() {
    let input = b"xyzxyzxyzxyzxyzxyzxyzxyz".repeat(4096);
    let compressed = compress(&input).unwrap();
    let reference = lz4_block::decompress(&compressed, Some(input.len() as i32)).unwrap();
    assert_eq!(reference, input);

    let reference_compressed = lz4_block::compress(&input, None, false).unwrap();
    let ours = decompress(&reference_compressed, input.len()).unwrap();
    assert_eq!(ours, input);
}

#[test]
fn interop_reference_matrix_allocating_api() {
    for input in interop_stress_inputs() {
        let expected_from_reference = lz4_block::decompress(
            &lz4_block::compress(&input, None, false).unwrap(),
            Some(input.len() as i32),
        )
        .unwrap();
        assert_eq!(expected_from_reference, input);

        let reference_compressed = lz4_block::compress(&input, None, false).unwrap();
        let ours_from_reference = decompress(&reference_compressed, input.len()).unwrap();
        assert_eq!(ours_from_reference, expected_from_reference);

        let our_compressed = compress(&input).unwrap();
        let reference_from_ours = lz4_block::decompress(&our_compressed, Some(input.len() as i32)).unwrap();
        let ours_from_ours = decompress(&our_compressed, input.len()).unwrap();
        assert_eq!(reference_from_ours, input);
        assert_eq!(ours_from_ours, reference_from_ours);
    }
}

#[test]
fn interop_reference_matrix_buffer_api() {
    for input in interop_stress_inputs() {
        let reference_compressed = lz4_block::compress(&input, None, false).unwrap();
        let mut ours_output = vec![0u8; input.len()];
        let written = decompress_to_buffer(&reference_compressed, &mut ours_output).unwrap();
        ours_output.truncate(written);
        assert_eq!(written, input.len());
        assert_eq!(ours_output, input);

        let mut our_compressed = vec![0u8; max_compressed_size(input.len())];
        let our_written = compress_to_buffer(&input, &mut our_compressed).unwrap();
        our_compressed.truncate(our_written);

        let reference_from_ours = lz4_block::decompress(&our_compressed, Some(input.len() as i32)).unwrap();
        assert_eq!(reference_from_ours, input);

        let mut ours_from_ours = vec![0u8; input.len()];
        let out_written = decompress_to_buffer(&our_compressed, &mut ours_from_ours).unwrap();
        ours_from_ours.truncate(out_written);
        assert_eq!(ours_from_ours, reference_from_ours);
    }
}
