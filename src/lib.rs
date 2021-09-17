extern crate threadpool;
extern crate jemallocator;
extern crate crossbeam_channel;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod utils;
mod encrypt;
mod decrypt;
mod sort;
pub mod attack;

pub type Message = [u8; 3];
pub type Key = [u8; 3];
pub type RoundKeys = [[u8; 3]; 11];
pub type Register = [u8; 10];
