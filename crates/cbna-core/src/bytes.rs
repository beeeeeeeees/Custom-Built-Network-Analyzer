//! Bounds-checked big-endian reader used by every decoder.

use crate::error::{DecodeError, Result};

#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    layer: &'static str,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8], layer: &'static str) -> Self {
        Self { buf, pos: 0, layer }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            Err(DecodeError::Truncated {
                layer: self.layer,
                need: n,
                have: self.remaining(),
            })
        } else {
            Ok(())
        }
    }

    pub fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn peek_u8(&self) -> Result<u8> {
        self.need(1)?;
        Ok(self.buf[self.pos])
    }

    pub fn be_u16(&mut self) -> Result<u16> {
        let b = self.array::<2>()?;
        Ok(u16::from_be_bytes(b))
    }

    pub fn be_u24(&mut self) -> Result<u32> {
        let b = self.array::<3>()?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    pub fn be_u32(&mut self) -> Result<u32> {
        let b = self.array::<4>()?;
        Ok(u32::from_be_bytes(b))
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.need(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.need(n)?;
        self.pos += n;
        Ok(())
    }

    /// Consume everything left, leaving the reader empty.
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }

    /// Peek at the remainder without consuming it.
    pub fn peek_rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Carve a nested reader of exactly `n` bytes, advancing past it.
    ///
    /// Used for length-delimited containers (IP options, TLS extensions) so an
    /// inner decoder cannot run off the end of its parent.
    pub fn sub(&mut self, n: usize, layer: &'static str) -> Result<Reader<'a>> {
        Ok(Reader::new(self.take(n)?, layer))
    }

    /// Truncate the reader so it exposes at most `n` more bytes.
    ///
    /// IP headers carry a total length that may be shorter than the captured
    /// frame (padding to the Ethernet minimum), so upper layers must not see
    /// trailing filler.
    pub fn limit(&mut self, n: usize) {
        let end = (self.pos + n).min(self.buf.len());
        self.buf = &self.buf[..end];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_big_endian() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03, 0x04, 0x05], "t");
        assert_eq!(r.u8().unwrap(), 0x01);
        assert_eq!(r.be_u16().unwrap(), 0x0203);
        assert_eq!(r.remaining(), 2);
        assert_eq!(r.rest(), &[0x04, 0x05]);
        assert!(r.is_empty());
    }

    #[test]
    fn truncation_reports_shortfall() {
        let mut r = Reader::new(&[0x01], "eth");
        let err = r.be_u32().unwrap_err();
        assert_eq!(
            err,
            DecodeError::Truncated {
                layer: "eth",
                need: 4,
                have: 1
            }
        );
    }

    #[test]
    fn limit_hides_padding() {
        let mut r = Reader::new(&[1, 2, 3, 4, 5, 6], "ip");
        r.skip(1).unwrap();
        r.limit(2);
        assert_eq!(r.rest(), &[2, 3]);
    }
}
