use std::cmp::Ordering;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Instant;

// use crate::ThreadPool;
use crate::utils::{ Message, Key, RoundKeys };

const DIC_SIZE: usize = 0xffffff;
const MSG_MASK: u64 = 0xffffff;
const MASK_K64: u64 = 0xffffff000000;

struct Dictionaries {
    enc: Vec<u64>,
    dec: Vec<u64>,
}

impl Dictionaries {
    fn new() -> Self {
        Dictionaries {
            enc: Vec::with_capacity(DIC_SIZE),
            dec: Vec::with_capacity(DIC_SIZE),
        }
    }

    fn generate(
        start: &usize,
        end: &usize,
        m: &Message,
        c: &Message
    ) -> Self {
        let mut enc = Vec::with_capacity(end - start);
        let mut dec = Vec::with_capacity(end - start);

        for i in *start..*end {
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

        Dictionaries { enc, dec }
    }

    fn sort(&mut self) {
        let mut tmp = vec![0; DIC_SIZE];

        radix_sort(&mut self.enc, &mut tmp, DIC_SIZE);
        radix_sort(&mut self.dec, &mut tmp, DIC_SIZE);
    }

    fn attack(&self, start: &usize, end: &usize, m: &Message, c: &Message) {
        for i in *start..*end {
            let index = bin_search(&self.dec, &self.enc[i], &m, &c);

            match index {
                Some(j) => check_collision(&self.enc[i], &self.dec[j], &m, &c),
                None => continue,
            }
        }
    }
}

fn radix_sort_pass(src: &mut [u64], dst: &mut [u64], n: usize, shift: usize) {
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

fn radix_sort(vec: &mut [u64], tmp: &mut [u64], n: usize) {
    radix_sort_pass(vec, tmp, n, 0);
    println!("pass 1");
    radix_sort_pass(tmp, vec, n, 8);
    println!("pass 2");
    radix_sort_pass(vec, tmp, n, 16);
    println!("pass 3");

    for i in 0..n {
        vec[i] = tmp[i];
    }
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
    let mut lo = 0;
    let mut hi = dic.len();

    while lo < hi {
        let mid = (hi + lo) / 2;
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

pub fn present24_attack(
    m1: Message,
    m2: Message,
    c1: Message,
    c2: Message,
    nb_threads: usize
) {
    let mut d = Dictionaries::new();
    let (tx, rx) = mpsc::channel();
    let mut handles = vec![];

    // print!("Generating dictionaries... ");
    let start = Instant::now();

    for i in 0..nb_threads {
        let start = i * (DIC_SIZE / nb_threads);
        let end = (i + 1) * (DIC_SIZE / nb_threads);
        println!("start: {}\tend: {}\tframe: {}\top: {}", start, end, end - start, DIC_SIZE / nb_threads);

        let ty = tx.clone();
        let handle = thread::spawn(move || {
            let d = Dictionaries::generate(&start, &end, &m1, &c1);

            ty.send(d).expect("Failed to send dictionaries");
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    for _ in 0..nb_threads {
        let mut received = rx.recv().unwrap();
        d.enc.append(&mut received.enc);
        d.dec.append(&mut received.dec);
    }

    let duration = start.elapsed();
    println!("done in {:?}", duration);

    // print!("Sorting dictionaries... ");
    let start = Instant::now();
    d.sort();
    let duration = start.elapsed();
    println!("done in {:?}", duration);

    // println!("Attacking dictionaries... ");
    let mut handles = vec![];
    let d = Arc::new(d);
    let start = Instant::now();

    for i in 0..nb_threads {
        let start = i * (DIC_SIZE / nb_threads);
        let end = (i + 1) * (DIC_SIZE / nb_threads);

        let dx = Arc::clone(&d);
        let handle = thread::spawn(move || {
            dx.attack(&start, &end, &m2, &c2);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let duration = start.elapsed();
    println!("\nAttack done in {:?}", duration);
}
