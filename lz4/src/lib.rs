use core::fmt;

const MIN_MATCH: usize = 4;
const LAST_LITERALS: usize = 5;
const MFLIMIT: usize = 12;
const HASH_LOG: usize = 16;
const HASH_SIZE: usize = 1 << HASH_LOG;
const HASH_SEED: u32 = 2_654_435_761;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    DestinationTooSmall,
    CorruptData,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DestinationTooSmall => f.write_str("destination buffer too small"),
            Error::CorruptData => f.write_str("corrupt lz4 block"),
        }
    }
}

impl std::error::Error for Error {}

pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = vec![0; max_compressed_size(data.len())];
    let written = compress_to_buffer(data, &mut output)?;
    output.truncate(written);
    Ok(output)
}

pub fn compress_to_buffer(source: &[u8], destination: &mut [u8]) -> Result<usize> {
    let mut dest_pos = 0usize;
    let mut anchor = 0usize;
    let mut pos = 0usize;
    let src_len = source.len();
    let mut hash_table = [usize::MAX; HASH_SIZE];

    if src_len >= MFLIMIT {
        while pos + MFLIMIT <= src_len {
            let sequence = read_u32(source, pos);
            let hash_index = hash(sequence);
            let candidate = hash_table[hash_index];
            hash_table[hash_index] = pos;

            if candidate != usize::MAX
                && pos > candidate
                && pos - candidate <= u16::MAX as usize
                && candidate + MIN_MATCH <= src_len
                && read_u32(source, candidate) == sequence
            {
                let literal_length = pos - anchor;
                let mut match_length = MIN_MATCH;
                let match_limit = src_len - LAST_LITERALS;
                while pos + match_length < match_limit && source[candidate + match_length] == source[pos + match_length]
                {
                    match_length += 1;
                }

                let mut token = 0u8;
                token |= encode_length_nibble(literal_length) << 4;
                token |= encode_length_nibble(match_length - MIN_MATCH);
                write_byte(destination, &mut dest_pos, token)?;
                write_extended_length(destination, &mut dest_pos, literal_length)?;
                write_slice(destination, &mut dest_pos, &source[anchor..pos])?;

                let offset = (pos - candidate) as u16;
                write_byte(destination, &mut dest_pos, (offset & 0x00FF) as u8)?;
                write_byte(destination, &mut dest_pos, (offset >> 8) as u8)?;

                write_extended_length(destination, &mut dest_pos, match_length - MIN_MATCH)?;

                let match_start = pos;
                pos += match_length;
                anchor = pos;

                let mut update = match_start + 1;
                while update + MIN_MATCH <= pos {
                    hash_table[hash(read_u32(source, update))] = update;
                    update += 1;
                }
            } else {
                pos += 1;
            }
        }
    }

    let literal_length = src_len - anchor;
    let token = encode_length_nibble(literal_length) << 4;
    write_byte(destination, &mut dest_pos, token)?;
    write_extended_length(destination, &mut dest_pos, literal_length)?;
    write_slice(destination, &mut dest_pos, &source[anchor..])?;

    Ok(dest_pos)
}

pub fn decompress(data: &[u8], capacity: usize) -> Result<Vec<u8>> {
    let mut output = vec![0; capacity];
    let written = decompress_to_buffer(data, &mut output)?;
    output.truncate(written);
    Ok(output)
}

pub fn decompress_to_buffer(source: &[u8], destination: &mut [u8]) -> Result<usize> {
    let mut src_pos = 0usize;
    let mut dest_pos = 0usize;

    while src_pos < source.len() {
        let token = source[src_pos];
        src_pos += 1;

        let literal_length = read_length((token >> 4) as usize, source, &mut src_pos)?;
        let literal_end = src_pos.checked_add(literal_length).ok_or(Error::CorruptData)?;
        let dest_end = dest_pos.checked_add(literal_length).ok_or(Error::CorruptData)?;

        if literal_end > source.len() {
            return Err(Error::CorruptData);
        }
        if dest_end > destination.len() {
            return Err(Error::DestinationTooSmall);
        }

        destination[dest_pos..dest_end].copy_from_slice(&source[src_pos..literal_end]);
        src_pos = literal_end;
        dest_pos = dest_end;

        if src_pos == source.len() {
            break;
        }

        if src_pos + 2 > source.len() {
            return Err(Error::CorruptData);
        }
        let offset = u16::from_le_bytes([source[src_pos], source[src_pos + 1]]) as usize;
        src_pos += 2;

        if offset == 0 || offset > dest_pos {
            return Err(Error::CorruptData);
        }

        let match_length = read_length((token & 0x0F) as usize, source, &mut src_pos)?
            .checked_add(MIN_MATCH)
            .ok_or(Error::CorruptData)?;

        let match_end = dest_pos.checked_add(match_length).ok_or(Error::CorruptData)?;
        if match_end > destination.len() {
            return Err(Error::DestinationTooSmall);
        }

        for _ in 0..match_length {
            let byte = destination[dest_pos - offset];
            destination[dest_pos] = byte;
            dest_pos += 1;
        }
    }

    Ok(dest_pos)
}

fn hash(sequence: u32) -> usize {
    ((sequence.wrapping_mul(HASH_SEED)) >> (32 - HASH_LOG)) as usize
}

fn read_u32(input: &[u8], index: usize) -> u32 {
    u32::from_le_bytes([input[index], input[index + 1], input[index + 2], input[index + 3]])
}

fn encode_length_nibble(length: usize) -> u8 {
    core::cmp::min(length, 15) as u8
}

fn write_extended_length(destination: &mut [u8], dest_pos: &mut usize, length: usize) -> Result<()> {
    if length < 15 {
        return Ok(());
    }

    let mut remaining = length - 15;
    while remaining >= 255 {
        write_byte(destination, dest_pos, 255)?;
        remaining -= 255;
    }
    write_byte(destination, dest_pos, remaining as u8)?;
    Ok(())
}

fn write_byte(destination: &mut [u8], dest_pos: &mut usize, value: u8) -> Result<()> {
    if *dest_pos >= destination.len() {
        return Err(Error::DestinationTooSmall);
    }
    destination[*dest_pos] = value;
    *dest_pos += 1;
    Ok(())
}

fn write_slice(destination: &mut [u8], dest_pos: &mut usize, source: &[u8]) -> Result<()> {
    let end = dest_pos.checked_add(source.len()).ok_or(Error::CorruptData)?;
    if end > destination.len() {
        return Err(Error::DestinationTooSmall);
    }
    destination[*dest_pos..end].copy_from_slice(source);
    *dest_pos = end;
    Ok(())
}

fn read_length(initial: usize, source: &[u8], src_pos: &mut usize) -> Result<usize> {
    if initial < 15 {
        return Ok(initial);
    }

    let mut length = 15usize;
    loop {
        if *src_pos >= source.len() {
            return Err(Error::CorruptData);
        }
        let value = source[*src_pos] as usize;
        *src_pos += 1;
        length = length.checked_add(value).ok_or(Error::CorruptData)?;
        if value != 255 {
            break;
        }
    }
    Ok(length)
}

fn max_compressed_size(source_len: usize) -> usize {
    source_len + (source_len / 255) + 16
}
