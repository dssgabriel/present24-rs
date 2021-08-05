use std::cmp::Ordering;
use std::time::Instant;
use crate::ThreadPool;
use crate::utils::{ Message, Key, RoundKeys };

const DIC_SIZE: usize = 0xffffff;
const MSG_MASK: u64 = 0xffffff;
const MASK_K64: u64 = 0xffffff000000;

fn generate_dictionaries(
    enc: &mut Vec<u64>,
    dec: &mut Vec<u64>,
    start: usize,
    end: usize,
    m: &Message,
    c: &Message
) {
    for i in start..end {
        let k: Key = [
            ((i & 0xff0000) >> 16) as u8,
            ((i & 0xff00) >> 8) as u8,
             (i & 0xff) as u8
        ];

        let mut enc_entry = ((k[0] as u64) << 16) | ((k[1] as u64) << 8) | (k[2] as u64);
        let mut dec_entry = ((k[0] as u64) << 16) | ((k[1] as u64) << 8) | (k[2] as u64);

        enc_entry <<= 24;
        dec_entry <<= 24;

        let rk: RoundKeys = crate::utils::generate_round_keys(k);

        let enc_res = crate::encrypt::present24_encrypt(*m, rk);
        let dec_res = crate::decrypt::present24_decrypt(*c, rk);

        enc_entry |= ((enc_res[0] as u64) << 16) | ((enc_res[1] as u64) << 8) | (enc_res[2] as u64);
        dec_entry |= ((dec_res[0] as u64) << 16) | ((dec_res[1] as u64) << 8) | (dec_res[2] as u64);

        enc.push(enc_entry);
        dec.push(dec_entry);
    }
}

fn radix_sort_pass(src: &mut Vec<u64>, dst: &mut Vec<u64>, n: usize, shift: usize) {
    let mut index = [0; 256];
    let mut next_index = 0;

    for i in 0..n {
        index[((src[i] >> shift) & 0xff) as usize] += 1;
    }

    for i in 0..256 {
        let count = index[i];
        index[i] = next_index;
        next_index += count;
    }

    for i in 0..n {
        let j = ((src[i] >> shift) & 0xff) as usize;
        dst[index[j]] = src[i];
        index[j] += 1; // Increase by one to get the next position.
    }
}

fn radix_sort(vec: &mut Vec<u64>, tmp: &mut Vec<u64>, n: usize) {
    radix_sort_pass(vec, tmp, n, 0);
    radix_sort_pass(tmp, vec, n, 8);
    radix_sort_pass(vec, tmp, n, 16);

    for i in 0..n {
        vec[i] = tmp[i];
    }
}

fn sort_dictionaries(enc: &mut Vec<u64>, dec: &mut Vec<u64>) {
    let mut tmp = vec![0; DIC_SIZE];

    radix_sort(enc, &mut tmp, DIC_SIZE);
    radix_sort(dec, &mut tmp, DIC_SIZE);
}

fn check_collision(enc: &u64, dec: &u64, m: &Message, c: &Message) {
    let kenc = enc & MASK_K64;
    let kdec = dec & MASK_K64;

    let k1: Key = [(kenc >> 40) as u8, (kenc >> 32) as u8, (kenc >> 24) as u8];
    let k2: Key = [(kdec >> 40) as u8, (kdec >> 32) as u8, (kdec >> 24) as u8];

    let rk1 = crate::utils::generate_round_keys(k1);
    let rk2 = crate::utils::generate_round_keys(k2);

    let renc = crate::encrypt::present24_encrypt(*m, rk1);
    let rdec = crate::decrypt::present24_decrypt(*c, rk2);

    if (renc[0] == rdec[0]) && (renc[1] == rdec[1]) && (renc[2] == rdec[2]) {
        println!("Found matching keys.\n    k1: {:06x} | k2: {:06x}",
            (enc & MASK_K64) >> 24, (dec & MASK_K64) >> 24
        );
    }
}

fn bin_search(
    dic: &[u64],
    target: &u64,
    m: &Message,
    c: &Message
) -> Option<usize> {
    let mut lo: i64 = 0;
    let mut hi: i64 = dic.len() as i64;

    while lo < hi {
        let mid: i64 = ((hi + lo) / 2) as i64;
        let t = target & MSG_MASK;

        match t.cmp(&(dic[mid as usize] & MSG_MASK)) {
            Ordering::Equal => {
                let mut cur = mid - 1;
                while (cur >= lo) && (t == (dic[cur as usize] & MSG_MASK)) {
                    check_collision(target, &dic[cur as usize], m, c);
                    cur -= 1;
                }

                cur = mid + 1;
                while (cur < hi) && (t == (dic[cur as usize] & MSG_MASK)) {
                    check_collision(target, &dic[cur as usize], m, c);
                    cur += 1;
                }

                return Some(mid as usize);
            },
            Ordering::Greater => lo = mid + 1,
            Ordering::Less => hi = mid - 1,
        }
    }

    None
}

fn attack_dictionaries(
    enc: &mut Vec<u64>,
    dec: &mut Vec<u64>,
    m: &Message,
    c: &Message
) {
    for i in 0..DIC_SIZE {
        let index = bin_search(&dec, &enc[i], &m, &c);

        match index {
            Some(j) => check_collision(&enc[i], &dec[j], &m, &c),
            None => continue,
        }
    }
}

pub fn present24_attack(
    m1: &'static Message,
    m2: &'static Message,
    c1: &'static Message,
    c2: &'static Message,
    nb_threads: usize
) {
    let mut encrypted = Vec::with_capacity(DIC_SIZE);
    let mut decrypted = Vec::with_capacity(DIC_SIZE);

    let pool = ThreadPool::new(8);

    print!("Generating dictionaries... ");
    let start = Instant::now();

    for i in 0..8 {
        let start = i * (DIC_SIZE / nb_threads);
        let end = (i + 1) * (DIC_SIZE / nb_threads);

        pool.execute(|| {
            generate_dictionaries(
                &mut encrypted,
                &mut decrypted,
                start,
                end,
                &m1,
                &c1
            );
        });
    }

    let duration = start.elapsed();
    println!("done in {:?}", duration);

    print!("Sorting dictionaries... ");
    let start = Instant::now();
    sort_dictionaries(&mut encrypted, &mut decrypted);
    let duration = start.elapsed();
    println!("done in {:?}", duration);

    println!("Attacking dictionaries... ");
    attack_dictionaries(&mut encrypted, &mut decrypted, &m2, &c2);
    let duration = start.elapsed();
    println!("\nAttack done in {:?}", duration);
}
