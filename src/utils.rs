use crate::{Key, RoundKeys, Register};

#[inline(always)]
pub fn generate_round_keys(k: Key) -> RoundKeys {
    let mut rk: RoundKeys = [[0x00; 3]; 11];

    let mut reg: Register = [
        k[0], k[1], k[2], 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let mut tmp: Register = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];


    for i in 0..11 {
        rk[i][0] = reg[5];
        rk[i][1] = reg[6];
        rk[i][2] = reg[7];

        tmp[0] = reg[7] << 5 | reg[8] >> 3;
        tmp[1] = reg[8] << 5 | reg[9] >> 3;
        tmp[2] = reg[9] << 5 | reg[0] >> 3;
        tmp[3] = reg[0] << 5 | reg[1] >> 3;
        tmp[4] = reg[1] << 5 | reg[2] >> 3;
        tmp[5] = reg[2] << 5 | reg[3] >> 3;
        tmp[6] = reg[3] << 5 | reg[4] >> 3;
        tmp[7] = reg[4] << 5 | reg[5] >> 3;
        tmp[8] = reg[5] << 5 | reg[6] >> 3;
        tmp[9] = reg[6] << 5 | reg[7] >> 3;

        tmp[0] = (crate::encrypt::sbox_encrypt(tmp[0]) & 0xf0) | (tmp[0] & 0x0f);

        tmp[7] ^= ((i + 1) >> 1) as u8;
        tmp[8] ^= ((i + 1) << 7) as u8;

        for j in 0..10 {
            reg[j] = tmp[j];
        }
    }

    rk
}

#[inline]
pub fn print_cracked(ke: &u64, kd: &u64) {
    println!("  [CRACKED]: (k1, k2) = ({:06x}, {:06x})", ke, kd);
}
