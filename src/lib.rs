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

pub fn sha512(msg: &[u8]) -> [u8; 64] {
    let mut hs: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    let mut w: [u64; 80] = [0; 80];
    let mut chunks = msg.chunks_exact(128);
    for chunk in chunks.by_ref() {
        sha512_block(chunk.try_into().unwrap(), &mut hs, &mut w);
    }

    let rem = chunks.remainder();
    let rem_len = rem.len();
    let mut last_block: [u8; 128] = [0; 128];
    last_block[..rem_len].copy_from_slice(rem);
    last_block[rem_len] = 0x80;
    let msg_bit_len: u128 = msg.len() as u128 * 8;
    if rem_len < 112 {
        last_block[112..128].copy_from_slice(&msg_bit_len.to_be_bytes());
        sha512_block(&last_block, &mut hs, &mut w);
    } else {
        sha512_block(&last_block, &mut hs, &mut w);
        last_block[..112].fill(0);
        last_block[112..].copy_from_slice(&msg_bit_len.to_be_bytes());
        sha512_block(&last_block, &mut hs, &mut w);
    }
    let mut digest: [u8; 64] = [0; 64];
    for i in (0..64).step_by(8) {
        digest[i..i + 8].copy_from_slice(&hs[i / 8].to_be_bytes());
    }
    digest
}

pub fn sha512_block(block: &[u8; 128], hs: &mut [u64; 8], w: &mut [u64; 80]) {
    for (t, bw) in block.chunks(8).enumerate() {
        w[t] = u64::from_be_bytes(bw.try_into().unwrap());
    }
    for t in 16..80 {
        w[t] = ssig1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(ssig0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *hs;
    let (mut t1, mut t2);
    for t in 0..80 {
        t1 = h
            .wrapping_add(bsig1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        t2 = bsig0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    hs[0] = hs[0].wrapping_add(a);
    hs[1] = hs[1].wrapping_add(b);
    hs[2] = hs[2].wrapping_add(c);
    hs[3] = hs[3].wrapping_add(d);
    hs[4] = hs[4].wrapping_add(e);
    hs[5] = hs[5].wrapping_add(f);
    hs[6] = hs[6].wrapping_add(g);
    hs[7] = hs[7].wrapping_add(h);
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

fn ssig0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

fn ssig1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
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
