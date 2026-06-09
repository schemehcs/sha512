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

// clear memory footprint
impl Drop for Vars {
    fn drop(&mut self) {
        self.a = 0;
        self.b = 0;
        self.c = 0;
        self.d = 0;
        self.e = 0;
        self.f = 0;
        self.g = 0;
        self.h = 0;
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
        self.a
            .to_be_bytes()
            .into_iter()
            .chain(self.b.to_be_bytes())
            .chain(self.c.to_be_bytes())
            .chain(self.d.to_be_bytes())
            .chain(self.e.to_be_bytes())
            .chain(self.f.to_be_bytes())
            .chain(self.g.to_be_bytes())
            .chain(self.h.to_be_bytes())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap()
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

// clear memory footprint
impl Drop for State {
    fn drop(&mut self) {
        self.work.fill(0);
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
        if self.cursor <= 14 {
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

    pub fn write(&mut self, mut buf: &[u8]) -> &mut Self {
        while let Some(Chunk { bytes, consumed }) = self.buf.update(buf) {
            let n = u64::from_be_bytes(bytes.try_into().unwrap());
            self.state.update(n);
            buf = &buf[consumed..];
        }
        self
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

    #[inline]
    pub fn write_u8(&mut self, i: u8) {
        self.write(&[i]);
    }

    /// Writes a single `u16` into this hasher.
    #[inline]
    pub fn write_u16(&mut self, i: u16) {
        self.write(&i.to_ne_bytes());
    }

    /// Writes a single `u32` into this hasher.
    #[inline]
    pub fn write_u32(&mut self, i: u32) {
        self.write(&i.to_ne_bytes());
    }

    /// Writes a single `u64` into this hasher.
    #[inline]
    pub fn write_u64(&mut self, i: u64) {
        self.write(&i.to_ne_bytes());
    }

    /// Writes a single `u128` into this hasher.
    #[inline]
    pub fn write_u128(&mut self, i: u128) {
        self.write(&i.to_ne_bytes());
    }

    /// Writes a single `usize` into this hasher.
    #[inline]
    pub fn write_usize(&mut self, i: usize) {
        self.write(&i.to_ne_bytes());
    }

    /// Writes a single `i8` into this hasher.
    #[inline]
    pub fn write_i8(&mut self, i: i8) {
        self.write_u8(i as u8);
    }

    /// Writes a single `i16` into this hasher.
    #[inline]
    pub fn write_i16(&mut self, i: i16) {
        self.write_u16(i as u16);
    }

    /// Writes a single `i32` into this hasher.
    #[inline]
    pub fn write_i32(&mut self, i: i32) {
        self.write_u32(i as u32);
    }

    /// Writes a single `i64` into this hasher.
    #[inline]
    pub fn write_i64(&mut self, i: i64) {
        self.write_u64(i as u64);
    }

    /// Writes a single `i128` into this hasher.
    #[inline]
    pub fn write_i128(&mut self, i: i128) {
        self.write_u128(i as u128);
    }

    /// Writes a single `isize` into this hasher.
    #[inline]
    pub fn write_isize(&mut self, i: isize) {
        self.write_usize(i as usize);
    }

    #[inline]
    pub fn write_str(&mut self, s: &str) {
        self.write(s.as_bytes());
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
    fn len7_msg_works() {
        // exactly one u64 word
        let msg = "abcdefg".as_bytes();
        let expected = "d716a4188569b68ab1b6dfac178e570114cdf0ea3a1cc0e31486c3e41241bc6a76424e8c37ab26f096fc85ef9886c8cb634187f4fddff645fb099f1ff54c6b8c";
        // generate expected with: echo -n "abcdefgh" | sha512sum
        let digest = hex::encode(sha512(msg));
        assert_eq!(expected, digest);
    }

    #[test]
    fn len8_msg_works() {
        // exactly one u64 word
        let msg = "abcdefgh".as_bytes();
        let expected = "a3a8c81bc97c2560010d7389bc88aac974a104e0e2381220c6e084c4dccd1d2d17d4f86db31c2a851dc80e6681d74733c55dcd03dd96f6062cdda12a291ae6ce";
        // generate expected with: echo -n "abcdefgh" | sha512sum
        let digest = hex::encode(sha512(msg));
        assert_eq!(expected, digest);
    }

    #[test]
    fn len111_msg_works() {
        // exactly one u64 word
        let msg = "a3a8c81bc97c2560010d7389bc88aac974a104e0e2381220c6e084c4dccd1d2d17d4f86db31c2a851dc80e6681d74733c55dcd03dd96fff".as_bytes();
        let expected = "4d859f9fe8482605fe43acf610b4dd252f964cab2d153bc5649e999b95c8c006a9e74a8a708f112aa6c4035b64eee708f7058e79f13364fe208c7112cf8a6bb3";
        // generate expected with: echo -n "abcdefgh" | sha512sum
        let digest = hex::encode(sha512(msg));
        assert_eq!(expected, digest);
    }

    #[test]
    fn len112_msg_works() {
        // exactly one u64 word
        let msg = "a3a8c81bc97c2560010d7389bc88aac974a104e0e2381220c6e084c4dccd1d2d17d4f86db31c2a851dc80e6681d74733c55dcd03dd96ffff".as_bytes();
        let expected = "eda0a89f4a6b657463374a872fe207c5ba9d82374f947210ef37ffb6d5248aaf012e4e9ebb798039e4c0c2f623735a527ed355bcd026736025f8b60aab60e640";
        // generate expected with: echo -n "abcdefgh" | sha512sum
        let digest = hex::encode(sha512(msg));
        assert_eq!(expected, digest);
    }

    #[test]
    fn len113_msg_works() {
        // exactly one u64 word
        let msg = "a3a8c81bc97c2560010d7389bc88aac974a104e0e2381220c6e084c4dccd1d2d17d4f86db31c2a851dc80e6681d74733c55dcd03dd96fffff".as_bytes();
        let expected = "d9ecdccdd9b343be7b62d929adda995497f476985f620704c7b8ffa594434260a95ffe5bc081894808859e9723a436195cb2079012e2725a8e50e9d6594e3136";
        // generate expected with: echo -n "abcdefgh" | sha512sum
        let digest = hex::encode(sha512(msg));
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

    #[test]
    fn long_text_works() {
        let mut hasher = Sha512::new();
        let msg = "9032fb94055d4d14e42185bdff59642b98fe6073f68f29d394620c4e698a86fb2e51351ca6997e6a164aae0b871cf789fbc6e0d863733d05903b4eb11be58d9c9032fb94055d4d1\
        4e42185bdff59642b98fe6073f68f29d394620c4e698a86fb2e51351ca6997e6a164aae0b871cf789fbc6e0d863733d05903b4eb11be58d9c9032fb94055d4d14e42185bdff59642b98fe6073f68f29d39\
        4620c4e698a86fb2e51351ca6997e6a164aae0b871cf789fbc6e0d863733d05903b4eb11be58d9ca3a8c81bc97c2560010d7389bc88aac974a104e0e2381220c6e084c4dccd1d2d17d4f86db31c2a851dc\
        80e6681d74733c55dcd03dd96fffffabfslfjlsjfljl";
        hasher.write_str(msg);
        let expected = "29692643bd8a4ef7aede1322b1ce892a8c1c1562adb84d532e5ba9928cd8f81a1773e5a49ea4a9b7ecaa79e493c7dffc0d15b675a87bdc9d0d1b7e9daffd218d";
        let digest = hex::encode(hasher.finish());
        assert_eq!(expected, digest);
    }

    #[test]
    fn accumulate_test() {
        let msg = "9032fb94055d4d14e42185bdff59642b98fe6073f68f29d394620c4e698a86fb2e51351ca6997e6a164aae0b871cf789fbc6e0d863733d05903b4eb11be58d9c9032fb94055d4d1\
        4e42185bdff59642b98fe6073f68f29d394620c4e698a86fb2e51351ca6997e6a164aae0b871cf789fbc6e0d863733d05903b4eb11be58d9c9032fb94055d4d14e42185bdff59642b98fe6073f68f29d39\
        4620c4e698a86fb2e51351ca6997e6a164aae0b871cf789fbc6e0d863733d05903b4eb11be58d9ca3a8c81bc97c2560010d7389bc88aac974a104e0e2381220c6e084c4dccd1d2d17d4f86db31c2a851dc\
        80e6681d74733c55dcd03dd96fffffabfslfjlsjfljl".as_bytes();
        let expected = "29692643bd8a4ef7aede1322b1ce892a8c1c1562adb84d532e5ba9928cd8f81a1773e5a49ea4a9b7ecaa79e493c7dffc0d15b675a87bdc9d0d1b7e9daffd218d";
        let mut hasher = Sha512::new();
        for ch in msg {
            hasher.write(&[*ch]);
        }
        let digest = hex::encode(hasher.finish());
        assert_eq!(expected, digest);
    }
}
