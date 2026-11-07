#![no_std]
#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

use cipher::{
    Block, BlockSizeUser, Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser, ParBlocksSizeUser,
    StreamCipherBackend, StreamCipherClosure, StreamCipherCore, StreamCipherCoreWrapper,
    consts::{U1, U32},
};
use core::array::from_fn;

/// PANAMA stream cipher.
pub type Panama = StreamCipherCoreWrapper<PanamaCore>;

/// Core state of the PANAMA stream cipher.
pub struct PanamaCore {
    a: [u32; 17],
    b: [[u32; 8]; 32],
}

impl PanamaCore {
    fn step(&mut self, p: Option<[u32; 8]>) {
        let ell = p.unwrap_or(self.b[4]);
        let q = p.unwrap_or_else(|| from_fn(|i| self.a[i + 1]));

        // rho = sigma o theta o pi o gamma, equations (3)-(8).
        let gamma: [u32; 17] =
            from_fn(|i| self.a[i] ^ (self.a[(i + 1) % 17] | !self.a[(i + 2) % 17]));
        let pi: [u32; 17] =
            from_fn(|i| gamma[7 * i % 17].rotate_left((i * (i + 1) / 2 % 32) as u32));
        let theta = from_fn(|i| pi[i] ^ pi[(i + 1) % 17] ^ pi[(i + 4) % 17]);
        self.a = theta;
        self.a[0] ^= 1;
        for i in 0..8 {
            self.a[i + 1] ^= ell[i];
            self.a[i + 9] ^= self.b[16][i];
        }

        // lambda, equations (1)-(2): shifted b[0] is OLD b[31].
        self.b.rotate_right(1);
        self.b[25] = from_fn(|i| self.b[25][i] ^ self.b[0][(i + 2) % 8]);
        self.b[0] = from_fn(|i| self.b[0][i] ^ q[i]);
    }
}

impl KeySizeUser for PanamaCore {
    type KeySize = U32;
}

impl IvSizeUser for PanamaCore {
    type IvSize = U32;
}

impl KeyIvInit for PanamaCore {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        let mut c = Self {
            a: [0; 17],
            b: [[0; 8]; 32],
        };
        // Table 2: Reset, Push K, Push Q (IV), then 32 blank Pulls.
        for bytes in [key.as_slice(), iv.as_slice()] {
            c.step(Some(from_fn(|i| {
                u32::from_le_bytes(from_fn(|j| bytes[4 * i + j]))
            })));
        }
        for _ in 0..32 {
            c.step(None);
        }
        c
    }
}

impl BlockSizeUser for PanamaCore {
    type BlockSize = U32;
}

impl StreamCipherCore for PanamaCore {
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }

    fn process_with_backend(&mut self, f: impl StreamCipherClosure<BlockSize = U32>) {
        f.call(self);
    }
}

impl ParBlocksSizeUser for PanamaCore {
    type ParBlocksSize = U1;
}

impl StreamCipherBackend for PanamaCore {
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        // z_i = a_(i+9), before the Pull update, equation (9).
        for (out, word) in block.chunks_exact_mut(4).zip(&self.a[9..]) {
            out.copy_from_slice(&word.to_le_bytes());
        }
        self.step(None);
    }
}

#[cfg(feature = "zeroize")]
impl cipher::zeroize::ZeroizeOnDrop for PanamaCore {}

#[cfg(feature = "zeroize")]
impl Drop for PanamaCore {
    fn drop(&mut self) {
        use cipher::zeroize::Zeroize;
        self.a.zeroize();
        self.b.zeroize();
    }
}
