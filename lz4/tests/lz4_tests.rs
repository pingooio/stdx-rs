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
