use present24::attack;
use std::env;
use std::time::Instant;

fn main() {
    let m1 = [0xce, 0x15, 0x7a];
    let c1 = [0x0e, 0xd3, 0xf0];
    let m2 = [0x41, 0x81, 0xc8];
    let c2 = [0x65, 0x0e, 0x1e];

    let args: Vec<String> = env::args().collect();
    let nb_threads: usize = if args.len() > 1 {
        args[1]
            .parse::<usize>()
            .expect("Usage: cargo run --release -- NB_THREADS")
    } else {
        4
    };

    println!("Attacking 2PRESENT24 with {nb_threads} threads:");
    println!(
        "  (m1, c1) = ({:02x}{:02x}{:02x}, {:02x}{:02x}{:02x})",
        m1[0], m1[1], m1[2], c1[0], c1[1], c1[2]
    );
    println!(
        "  (m2, c2) = ({:02x}{:02x}{:02x}, {:02x}{:02x}{:02x})\n",
        m2[0], m2[1], m2[2], c2[0], c2[1], c2[2]
    );

    let start = Instant::now();
    attack::present24_attack(m1, m2, c1, c2, nb_threads);
    let duration = start.elapsed();
    println!("\nFinished in {:?}", duration);
}
