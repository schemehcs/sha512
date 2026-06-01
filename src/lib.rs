use chunk_buf::{Chunk, ChunkBuf};
use std::ops::AddAssign;

static K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

#[derive(Clone)]
struct Vars {
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
    f: u64,
    g: u64,
    h: u64,
}

impl Default for Vars {
    fn default() -> Self {
        Self {
            a: 0x6a09e667f3bcc908,
            b: 0xbb67ae8584caa73b,
            c: 0x3c6ef372fe94f82b,
            d: 0xa54ff53a5f1d36f1,
            e: 0x510e527fade682d1,
            f: 0x9b05688c2b3e6c1f,
            g: 0x1f83d9abfb41bd6b,
            h: 0x5be0cd19137e2179,
        }
    }
}

impl Vars {
    pub fn update(&mut self, work: &[u64; 80]) {
        let mut cln = self.clone();
        let (mut t1, mut t2);
        for t in 0..80 {
            t1 = cln
                .h
                .wrapping_add(Self::bsig1(cln.e))
                .wrapping_add(Self::ch(cln.e, cln.f, cln.g))
                .wrapping_add(K[t])
                .wrapping_add(work[t]);
            t2 = Self::bsig0(cln.a).wrapping_add(Self::maj(cln.a, cln.b, cln.c));
            cln.h = cln.g;
            cln.g = cln.f;
            cln.f = cln.e;
            cln.e = cln.d.wrapping_add(t1);
            cln.d = cln.c;
            cln.c = cln.b;
            cln.b = cln.a;
            cln.a = t1.wrapping_add(t2);
        }
        self.add_assign(cln);
    }

    pub fn digest(&self) -> [u8; 64] {
        let mut digest: [u8; 64] = [0; 64];
        digest[0..8].copy_from_slice(&self.a.to_be_bytes());
        digest[8..16].copy_from_slice(&self.b.to_be_bytes());
        digest[16..24].copy_from_slice(&self.c.to_be_bytes());
        digest[24..32].copy_from_slice(&self.d.to_be_bytes());
        digest[32..40].copy_from_slice(&self.e.to_be_bytes());
        digest[40..48].copy_from_slice(&self.f.to_be_bytes());
        digest[48..56].copy_from_slice(&self.g.to_be_bytes());
        digest[56..64].copy_from_slice(&self.h.to_be_bytes());
        digest
    }

    fn ch(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (!x & z)
    }

    fn maj(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn bsig0(x: u64) -> u64 {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }

    fn bsig1(x: u64) -> u64 {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }
}

impl AddAssign for Vars {
    fn add_assign(&mut self, rhs: Self) {
        self.a = self.a.wrapping_add(rhs.a);
        self.b = self.b.wrapping_add(rhs.b);
        self.c = self.c.wrapping_add(rhs.c);
        self.d = self.d.wrapping_add(rhs.d);
        self.e = self.e.wrapping_add(rhs.e);
        self.f = self.f.wrapping_add(rhs.f);
        self.g = self.g.wrapping_add(rhs.g);
        self.h = self.h.wrapping_add(rhs.h);
    }
}

#[derive(Clone)]
struct State {
    vars: Vars,
    work: [u64; 80],
    cursor: usize,
}

impl Default for State {
    fn default() -> Self {
        State {
            vars: Vars::default(),
            work: [0; 80],
            cursor: 0,
        }
    }
}

impl State {
    pub fn update(&mut self, n: u64) {
        self.work[self.cursor] = n;
        self.cursor += 1;
        if self.cursor < 16 {
            return;
        }
        self.expand();
        self.cursor = 0;
    }

    pub fn expand(&mut self) {
        for t in 16..80 {
            self.work[t] = Self::ssig1(self.work[t - 2])
                .wrapping_add(self.work[t - 7])
                .wrapping_add(Self::ssig0(self.work[t - 15]))
                .wrapping_add(self.work[t - 16]);
        }
        self.vars.update(&self.work);
    }

    pub fn finish(&mut self, n: u64, byte_len: usize) -> [u8; 64] {
        self.update(n);
        if self.cursor < 14 {
            self.work[self.cursor..14].fill(0);
            self.fill_len(byte_len);
            self.expand();
        } else {
            self.work[self.cursor..16].fill(0);
            self.expand();
            self.work[..14].fill(0);
            self.fill_len(byte_len);
            self.expand();
        }
        self.vars.digest()
    }

    fn fill_len(&mut self, byte_len: usize) {
        let bit_len: u128 = (byte_len as u128) * 8;
        self.work[14] = (bit_len >> 64) as u64;
        self.work[15] = bit_len as u64;
    }

    fn ssig0(x: u64) -> u64 {
        x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
    }

    fn ssig1(x: u64) -> u64 {
        x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
    }
}

#[derive(Clone)]
pub struct Sha512 {
    state: State,
    buf: ChunkBuf<u8>,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self {
            state: State::default(),
            buf: ChunkBuf::new(8),
        }
    }
}

impl Sha512 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write(&mut self, mut buf: &[u8]) {
        while let Some(Chunk { bytes, consumed }) = self.buf.update(buf) {
            let n = u64::from_be_bytes(bytes.try_into().unwrap());
            self.state.update(n);
            buf = &buf[consumed..];
        }
    }

    pub fn finish(&mut self) -> [u8; 64] {
        let n = match self.buf.update(&[0x80]) {
            Some(Chunk { bytes, .. }) => u64::from_be_bytes(bytes.try_into().unwrap()),
            None => {
                let mut last_u64 = [0u8; 8];
                let remainder = self.buf.remainder();
                last_u64[..remainder.len()].copy_from_slice(remainder);
                u64::from_be_bytes(last_u64)
            }
        };
        self.state.finish(n, self.buf.acc_consumed() - 1)
    }
}

pub fn sha512(msg: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.write(msg);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_msg_works() {
        let msg = [];
        let digest = hex::encode(sha512(&msg));
        let expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        assert_eq!(expected, digest);
    }

    #[test]
    fn len1_msg_works() {
        let msg = "H".as_bytes();
        let expected = "9032fb94055d4d14e42185bdff59642b98fe6073f68f29d394620c4e698a86fb2e51351ca6997e6a164aae0b871cf789fbc6e0d863733d05903b4eb11be58d9c";
        let digest = hex::encode(sha512(&msg));
        assert_eq!(expected, digest);
    }

    #[test]
    fn len127_msg_works() {
        let msg = "9032fb94055d4d14e42185bdff59642b98fe6073f68f29d394620c4e698a86fb2e51351ca6997e6a164aae0b871cf789fbc6e0d863733d05903b4eb11be58d9".as_bytes();
        let expected = "53c3f30b667f0b2f1735c779d6389490e49486cdb0ed42616af2c324c8b6eaaffb916bc5aa43921f06fc308b7744ca78b80c7893a6c1ea0a85883eab9d660456";
        let digest = hex::encode(sha512(&msg));
        assert_eq!(expected, digest);
    }

    #[test]
    fn len128_msg_works() {
        let msg = "9032fb94055d4d14e42185bdff59642b98fe6073f68f29d394620c4e698a86fb2e51351ca6997e6a164aae0b871cf789fbc6e0d863733d05903b4eb11be58d9c".as_bytes();
        let expected = "b591e01cadb9bbbbae79d62eca0acdca5b52494804c62c082aec76f3863210e8f811a0c431926ae9f6dc1b4fcec2adf925e00a5ad23069064190c4250772669e";
        let digest = hex::encode(sha512(&msg));
        assert_eq!(expected, digest);
    }
}
