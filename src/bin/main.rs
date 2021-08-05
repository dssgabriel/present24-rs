use std::time::Instant;
use present24::attack;

fn main() {
    let m1 = [0xb4, 0x04, 0xcc];
    let c1 = [0x23, 0x71, 0x4f];
    let m2 = [0x57, 0x6d, 0xcf];
    let c2 = [0x45, 0x05, 0x1b];

    println!("Man In The Middle attack on 2PRESENT24 with:");
    print!("    Message 1: {:02x}{:02x}{:02x} | ", m1[0], m1[1], m1[2]);
    println!("Cipher 1:  {:02x}{:02x}{:02x}", c1[0], c1[1], c1[2]);
    print!("    Message 2: {:02x}{:02x}{:02x} | ", m2[0], m2[1], m2[2]);
    println!("Cipher 2:  {:02x}{:02x}{:02x}\n", c2[0], c2[1], c2[2]);

    let start = Instant::now();
    attack::present24_attack(&m1, &m2, &c1, &c2);
    let duration = start.elapsed();
    println!("Program run in {:?}", duration);
}
