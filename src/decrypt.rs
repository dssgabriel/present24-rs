use crate::utils::{ Message, RoundKeys };

const SBOX_DECRYPT: [u8; 16] = [
    0x05, 0x0e, 0x0f, 0x08,
    0x0c, 0x01, 0x02, 0x0d,
    0x0b, 0x04, 0x06, 0x03,
    0x00, 0x07, 0x09, 0x0a
];

fn sbox_decrypt(byte: u8) -> u8 {
    let hi_nibble = SBOX_DECRYPT[((byte & 0xf0) >> 4) as usize] << 4;
    let lo_nibble = SBOX_DECRYPT[(byte & 0x0f) as usize];

    hi_nibble | lo_nibble
}

fn pbox_decrypt(m: &Message) -> Message {
    let p: Message = [
        (m[0] & 0x80)      | (m[0] & 0x02) << 5 |
        (m[1] & 0x08) << 2 | (m[2] & 0x20) >> 1 |
        (m[0] & 0x40) >> 3 | (m[0] & 0x01) << 2 |
        (m[1] & 0x04) >> 1 | (m[2] & 0x10) >> 4,

        (m[0] & 0x20) << 2 | (m[1] & 0x80) >> 1 |
        (m[1] & 0x02) << 4 | (m[2] & 0x08) << 1 |
        (m[0] & 0x10) >> 1 | (m[1] & 0x40) >> 4 |
        (m[1] & 0x01) << 1 | (m[2] & 0x04) >> 2,

        (m[0] & 0x08) << 4 | (m[1] & 0x20) << 1 |
        (m[2] & 0x80) >> 2 | (m[2] & 0x02) << 3 |
        (m[0] & 0x04) << 1 | (m[1] & 0x10) >> 2 |
        (m[2] & 0x40) >> 5 | (m[2] & 0x01)
    ];

    p
}

pub fn present24_decrypt(mut m: Message, rk: RoundKeys) -> Message {
    for i in 0..3 {
        m[i] ^= rk[10][i];
    }

    for i in (0..10).rev() {
        m = pbox_decrypt(&m);

        for j in 0..3 {
            m[j] = sbox_decrypt(m[j]);
            m[j] ^= rk[i][j];
        }
    }

    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;

    #[test]
    fn vector1() {
        let m = [0xbb, 0x57, 0xe6];
        let k = [0x00, 0x00, 0x00];

        let rk = utils::generate_round_keys(k);
        let res = present24_decrypt(m, rk);

        assert_eq!(res, [0x00, 0x00, 0x00]);
    }

    #[test]
    fn vector2() {
        let m = [0x73, 0x92, 0x93];
        let k = [0x00, 0x00, 0x00];

        let rk = utils::generate_round_keys(k);
        let res = present24_decrypt(m, rk);

        assert_eq!(res, [0xff, 0xff, 0xff]);
    }

    #[test]
    fn vector3() {
        let m = [0x1b, 0x56, 0xce];
        let k = [0xff, 0xff, 0xff];

        let rk = utils::generate_round_keys(k);
        let res = present24_decrypt(m, rk);

        assert_eq!(res, [0x00, 0x00, 0x00]);
    }

     #[test]
    fn vector4() {
        let m = [0x47, 0xa9, 0x29];
        let k = [0xd1, 0xbd, 0x2d];

        let rk = utils::generate_round_keys(k);
        let res = present24_decrypt(m, rk);

        assert_eq!(res, [0xf9, 0x55, 0xb9]);
    }
}
