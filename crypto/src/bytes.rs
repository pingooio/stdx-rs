use constant_time_eq::constant_time_eq;

/// A fixed-capacity, stack-allocated bytes buffer of capacity `N`.
/// Use [`Self::as_ref`] to get the bytes as a `&[u8]` and [`Self::as_mut`] to get the bytes as a `&mut [u8]`.
/// Comparing `Bytes` is a constant-time operation.
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Bytes<const N: usize> {
    bytes: [u8; N],
    length: u16,
}

impl<const N: usize> Bytes<N> {
    #[inline]
    pub(crate) fn new() -> Bytes<N> {
        assert!(N <= u16::MAX as usize);
        return Bytes {
            bytes: [0u8; N],
            length: 0,
        };
    }

    #[inline]
    pub(crate) fn with_length(length: usize) -> Bytes<N> {
        assert!(N <= u16::MAX as usize && length <= u16::MAX as usize);
        assert!(length <= N, "length exceeds capacity");
        return Bytes {
            bytes: [0u8; N],
            length: length as u16,
        };
    }

    #[inline]
    pub fn len(&self) -> usize {
        return self.length as usize;
    }

    pub(crate) fn push(&mut self, byte: u8) {
        assert!(self.length as usize + 1 <= N);
        self.bytes[self.length as usize] = byte;
        self.length += 1;
    }

    pub(crate) fn append(&mut self, data: &[u8]) {
        assert!(self.length as usize + data.len() <= N);
        self.bytes[self.length as usize..data.len() + self.length as usize].copy_from_slice(data);
        self.length += data.len() as u16;
    }
}

impl<const N: usize> PartialEq for Bytes<N> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.as_ref(), other.as_ref())
    }
}

impl<const N: usize> Eq for Bytes<N> {}

impl<const N: usize> AsRef<[u8]> for Bytes<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }
}

impl<const N: usize> AsMut<[u8]> for Bytes<N> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.length as usize]
    }
}
