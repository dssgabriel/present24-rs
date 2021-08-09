use std::env;
use std::time::Instant;
use present24::attack;

fn main() {
    let m1 = [0xce, 0x15, 0x7a];
    let c1 = [0x0e, 0xd3, 0xf0];
    let m2 = [0x41, 0x81, 0xc8];
    let c2 = [0x65, 0x0e, 0x1e];

    let args: Vec<String> = env::args().collect();
    let nb_threads: usize = args[1].parse::<usize>().unwrap();

    println!("Man In The Middle attack on 2PRESENT24 with:");
    print!("    Message 1: {:02x}{:02x}{:02x} | ", m1[0], m1[1], m1[2]);
    println!("Cipher 1:  {:02x}{:02x}{:02x}", c1[0], c1[1], c1[2]);
    print!("    Message 2: {:02x}{:02x}{:02x} | ", m2[0], m2[1], m2[2]);
    println!("Cipher 2:  {:02x}{:02x}{:02x}\n", c2[0], c2[1], c2[2]);

    let start = Instant::now();
    attack::present24_attack(m1, m2, c1, c2, nb_threads);
    let duration = start.elapsed();
    println!("Program run in {:?}", duration);
}
