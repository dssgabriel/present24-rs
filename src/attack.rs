use std::cmp::Ordering;
use std::sync::Arc;
use std::time::Instant;
use crossbeam_channel;
use threadpool::ThreadPool;
use crate::{Message, encrypt, decrypt, sort, utils};

const HTBL_SIZE: usize = 0xffffff;
const MSG_MASK: u64 = 0xffffff;
const KEY_MASK: u64 = 0xffffff000000;

struct HashTables {
    encrypt: Vec<u64>,
    decrypt: Vec<u64>
}

impl HashTables {
    fn new(size: usize) -> Self {
        HashTables {
            encrypt: Vec::with_capacity(size),
            decrypt: Vec::with_capacity(size),
        }
    }

    #[inline(always)]
    fn generate(start: usize, end: usize, m: &Message, c: &Message) -> Self {
        let mut hash_tables = Self::new(end - start);

        for i in start..end {
            let k = [
                ((i & 0xff0000) >> 16) as u8,
                ((i & 0xff00) >> 8) as u8,
                 (i & 0xff) as u8
            ];

            let entry = (((k[0] as u64) << 16) | ((k[1] as u64) << 8) | (k[2] as u64)) << 24;

            let rk = utils::generate_round_keys(k);

            let e = encrypt::present24_encrypt(*m, rk);
            let d = decrypt::present24_decrypt(*c, rk);

            let e = entry | (((e[0] as u64) << 16) | ((e[1] as u64) << 8) | (e[2] as u64));
            let d = entry | (((d[0] as u64) << 16) | ((d[1] as u64) << 8) | (d[2] as u64));

            hash_tables.encrypt.push(e);
            hash_tables.decrypt.push(d);
        }

        hash_tables
    }

    fn sort(&mut self) {
        let len = self.encrypt.len();
        let mut tmp = vec![0; len];

        sort::radix_sort(&mut self.encrypt, &mut tmp);
        sort::radix_sort(&mut self.decrypt, &mut tmp);
    }

    #[inline(always)]
    fn attack(&self, start: usize, end: usize, m: &Message, c: &Message) {
        for i in start..end {
            let index = binary_search(&self.decrypt, &self.encrypt[i], &m, &c);

            match index {
                Some(j) => check_collision(&self.encrypt[i], &self.decrypt[j], &m, &c),
                None => continue,
            }
        }
    }
}

#[inline(always)]
fn check_collision(e: &u64, d: &u64, m: &Message, c: &Message) {
    let ke = e & KEY_MASK;
    let kd = d & KEY_MASK;

    let k1 = [(ke >> 40) as u8, (ke >> 32) as u8, (ke >> 24) as u8];
    let k2 = [(kd >> 40) as u8, (kd >> 32) as u8, (kd >> 24) as u8];

    let rk1 = crate::utils::generate_round_keys(k1);
    let rk2 = crate::utils::generate_round_keys(k2);

    let re = crate::encrypt::present24_encrypt(*m, rk1);
    let rd = crate::decrypt::present24_decrypt(*c, rk2);

    if (re[0] == rd[0]) && (re[1] == rd[1]) && (re[2] == rd[2]) {
        utils::print_cracked(&((e & KEY_MASK) >> 24), &((d & KEY_MASK) >> 24));
    }
}

#[inline(always)]
fn binary_search(hash_table: &[u64], target: &u64, m: &Message, c: &Message) -> Option<usize> {
    let mut lo = 0;
    let mut hi = hash_table.len();

    while lo < hi {
        let mid = (hi + lo) / 2;
        let t = target & MSG_MASK;

        match t.cmp(&(hash_table[mid as usize] & MSG_MASK)) {
            Ordering::Equal => {
                let mut cur = mid - 1;
                while (cur >= lo) && (t == (hash_table[cur as usize] & MSG_MASK)) {
                    check_collision(target, &hash_table[cur as usize], m, c);
                    cur -= 1;
                }

                cur = mid + 1;
                while (cur < hi) && (t == (hash_table[cur as usize] & MSG_MASK)) {
                    check_collision(target, &hash_table[cur as usize], m, c);
                    cur += 1;
                }

                return Some(mid as usize);
            },
            Ordering::Greater => lo = mid + 1,
            Ordering::Less => hi = mid,
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
    let pool = ThreadPool::new(nb_threads);
    let (tx, rx) = crossbeam_channel::bounded(nb_threads);
    let mut hash_tables = HashTables::new(HTBL_SIZE);

    let time = Instant::now();
    for i in 0..nb_threads {
        let start = i * (HTBL_SIZE / nb_threads);
        let end = (i + 1) * (HTBL_SIZE / nb_threads);

        let ty = tx.clone();
        pool.execute(move || {
            let h = HashTables::generate(start, end, &m1, &c1);

            ty.send(h).expect("Failed to send hash table through channel");
        });
    }
    pool.join();

    for _ in 0..nb_threads {
        let mut received = rx.recv().unwrap();
        hash_tables.encrypt.append(&mut received.encrypt);
        hash_tables.decrypt.append(&mut received.decrypt);
    }
    let duration = time.elapsed();
    println!("Generated {} hashes in {:?}", HTBL_SIZE * 2, duration);

    let time = Instant::now();
    hash_tables.sort();
    let duration = time.elapsed();
    println!("Sorted hash tables in {:?}", duration);

    println!("Attacking hash tables...");
    let hash_tables = Arc::new(hash_tables);
    for i in 0..nb_threads {
        let start = i * (HTBL_SIZE / nb_threads);
        let end = (i + 1) * (HTBL_SIZE / nb_threads);

        let h = Arc::clone(&hash_tables);
        pool.execute(move || {
            h.attack(start, end, &m2, &c2);
        });
    }
    pool.join();
}
