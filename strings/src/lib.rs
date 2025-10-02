use itoa::Integer;
use ryu::Float;

pub fn itoa<I: Integer>(n: I) -> String {
    let mut buffer = itoa::Buffer::new();
    return buffer.format(n).to_string();
}

pub fn ftoa<F: Float>(n: F) -> String {
    let mut buffer = ryu::Buffer::new();
    return buffer.format(n).to_string();
}
