use crate::{Message, RoundKeys};

const SBOX_ENCRYPT: [u8; 16] = [
    0x0c, 0x05, 0x06, 0x0b,
    0x09, 0x00, 0x0a, 0x0d,
    0x03, 0x0e, 0x0f, 0x08,
    0x04, 0x07, 0x01, 0x02
];

#[inline(always)]
pub fn sbox_encrypt(byte: u8) -> u8 {
    let hi_nibble = SBOX_ENCRYPT[((byte & 0xf0) >> 4) as usize] << 4;
    let lo_nibble = SBOX_ENCRYPT[(byte & 0x0f) as usize];

    hi_nibble | lo_nibble
}

#[inline(always)]
fn pbox_encrypt(m: &Message) -> Message {
    let p: Message = [
        (m[0] & 0x80)      | (m[0] & 0x08) << 3 |
        (m[1] & 0x80) >> 2 | (m[1] & 0x08) << 1 |
        (m[2] & 0x80) >> 4 | (m[2] & 0x08) >> 1 |
        (m[0] & 0x40) >> 5 | (m[0] & 0x04) >> 2,

        (m[1] & 0x40) << 1 | (m[1] & 0x04) << 4 |
        (m[2] & 0x40) >> 1 | (m[2] & 0x04) << 2 |
        (m[0] & 0x20) >> 2 | (m[0] & 0x02) << 1 |
        (m[1] & 0x20) >> 4 | (m[1] & 0x02) >> 1,

        (m[2] & 0x20) << 2 | (m[2] & 0x02) << 5 |
        (m[0] & 0x10) << 1 | (m[0] & 0x01) << 4 |
        (m[1] & 0x10) >> 1 | (m[1] & 0x01) << 2 |
        (m[2] & 0x10) >> 3 | (m[2] & 0x01)
    ];

    p
}

#[inline(always)]
pub fn present24_encrypt(mut m: Message, rk: RoundKeys) -> Message {
    for i in 0..10 {
        for j in 0..3 {
            m[j] ^= rk[i][j];
            m[j] = sbox_encrypt(m[j]);
        }

        m = pbox_encrypt(&m);
    }

    for i in 0..3 {
        m[i] ^= rk[10][i];
    }

    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;

    #[test]
    fn vector1() {
        let m = [0x00, 0x00, 0x00];
        let k = [0x00, 0x00, 0x00];

        let rk = utils::generate_round_keys(k);
        let res = present24_encrypt(m, rk);

        assert_eq!(res, [0xbb, 0x57, 0xe6]);
    }

    #[test]
    fn vector2() {
        let m = [0xff, 0xff, 0xff];
        let k = [0x00, 0x00, 0x00];

        let rk = utils::generate_round_keys(k);
        let res = present24_encrypt(m, rk);

        assert_eq!(res, [0x73, 0x92, 0x93]);
    }

    #[test]
    fn vector3() {
        let m = [0x00, 0x00, 0x00];
        let k = [0xff, 0xff, 0xff];

        let rk = utils::generate_round_keys(k);
        let res = present24_encrypt(m, rk);

        assert_eq!(res, [0x1b, 0x56, 0xce]);
    }

     #[test]
    fn vector4() {
        let m = [0xf9, 0x55, 0xb9];
        let k = [0xd1, 0xbd, 0x2d];

        let rk = utils::generate_round_keys(k);
        let res = present24_encrypt(m, rk);

        assert_eq!(res, [0x47, 0xa9, 0x29]);
    }
}
