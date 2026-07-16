//! Fiat–Shamir challenge derivation.
//!
//! Turns a proof transcript seed into a P-384 [`Scalar`] challenge by hashing a
//! counter-prefixed SHA-256 stream and rejection-sampling the first block that
//! forms a valid scalar.

use p384::elliptic_curve::common::Output;
use p384::elliptic_curve::PrimeField;
use p384::{FieldBytes, Scalar};
use sha2::{Digest, Sha256};

pub fn challenge(seed: &[u8]) -> Scalar {
    let mut stream = HashStream::new(seed);

    loop {
        let mut candidate = FieldBytes::default();
        for byte in &mut candidate {
            *byte = stream.next_byte();
        }

        if let Some(scalar) = Option::<Scalar>::from(Scalar::from_repr(candidate)) {
            return scalar;
        }
    }
}

struct HashStream<'a> {
    seed: &'a [u8],
    counter: u64,
    block: Output<Sha256>,
    pos: usize,
}

impl<'a> HashStream<'a> {
    fn new(seed: &'a [u8]) -> Self {
        Self {
            seed,
            counter: 0,
            block: Output::<Sha256>::default(),
            pos: Sha256::output_size(),
        }
    }

    fn next_byte(&mut self) -> u8 {
        if self.pos >= self.block.len() {
            self.counter = self.counter.wrapping_add(1);
            self.block = Sha256::new()
                .chain_update(self.counter.to_be_bytes())
                .chain_update(self.seed)
                .finalize();
            self.pos = 0;
        }

        let byte = self.block.get(self.pos).copied().unwrap_or_default();
        self.pos += 1;
        byte
    }
}
