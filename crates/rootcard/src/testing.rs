//! A deterministic byte stream for tests and test vectors. **Never** use it for keys or nonces.
//!
//! The stream is `SHA-256(seed ‖ be32(0)) ‖ SHA-256(seed ‖ be32(1)) ‖ …`, consumed byte by byte, so that the Rust and
//! JavaScript implementations draw the same bytes in the same order ([IMP-1], SPEC §21).

use crate::crypto::sha256;

/// A deterministic random stream for tests.
pub struct TestRandom {
    seed: Vec<u8>,
    counter: u32,
    buf: Vec<u8>,
}

impl TestRandom {
    /// A stream from `seed`.
    pub fn new(seed: &[u8]) -> Self {
        TestRandom {
            seed: seed.to_vec(),
            counter: 0,
            buf: Vec::new(),
        }
    }

    /// Fill `out` with the next bytes of the stream.
    pub fn fill(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            if self.buf.is_empty() {
                let mut m = self.seed.clone();
                m.extend_from_slice(&self.counter.to_be_bytes());
                self.counter += 1;
                self.buf = sha256(&m).iter().rev().copied().collect();
            }
            *b = self.buf.pop().unwrap_or(0);
        }
    }

    /// The next `N` bytes.
    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        self.fill(&mut b);
        b
    }
}
