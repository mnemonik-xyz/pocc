#![no_main]
risc0_zkvm::guest::entry!(main);

fn main() {
    let input: bench_core::Input = risc0_zkvm::guest::env::read();
    let (total, commit) = bench_core::check(&input).expect("denied");
    risc0_zkvm::guest::env::commit(&(total, commit));
}
