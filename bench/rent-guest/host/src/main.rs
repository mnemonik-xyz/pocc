use bench_core::*;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv};
use sha2::{Digest, Sha256};
use std::time::Instant;

fn key(seed: u8) -> SigningKey { SigningKey::from_bytes(&[seed; 32].into()).unwrap() }
fn sign(k: &SigningKey, msg: &[u8]) -> Vec<u8> { let s: Signature = k.sign(msg); s.normalize_s().unwrap_or(s).to_bytes().to_vec() }

fn input(hours: u32) -> Input {
    let meter = key(7); let acc = key(9);
    let scope = Scope { chain_id: 5042002, vault: [0x11; 20], token: [0x36; 20] };
    let start = 1794819600u64; let price = 1100u64;
    let (mut records, mut notes) = (vec![], vec![]);
    for k in 0..hours {
        let creditable = if k == 0 { 3540 } else { 3600 };
        let rec = UsageRecord { scope: scope.clone(), lease_id: [0x42; 32], first_index: k, last_index: k,
            window_start: start + k as u64 * 3600, window_end: start + (k as u64 + 1) * 3600,
            units: creditable, creditable, assurance: 0, meter_spec: [0x55; 32], deliverable_hash: [0x66; 32] };
        let rmsg = tagged_bytes(b"warrant/usage/v1", &rec);
        let rhash: Hash = Sha256::digest(&rmsg).into();
        let note = Note { scope: scope.clone(), task_id: [k as u8; 32], deliverable_hash: rhash, recipient: [0x22; 20],
            amount: creditable * price, accepted: true, valid_after: start, valid_until: start + 1_000_000 };
        let nmsg = tagged_bytes(b"warrant/acceptance/v1", &note);
        records.push((rec, sign(&meter, &rmsg)));
        notes.push((note, sign(&acc, &nmsg)));
    }
    Input { meter_key: meter.verifying_key().to_sec1_bytes().to_vec(), acceptance_key: acc.verifying_key().to_sec1_bytes().to_vec(),
        price_per_unit: price, records, notes }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("execute");
    let hours: Vec<u32> = args.iter().skip(2).map(|s| s.parse().unwrap()).collect();
    let hours = if hours.is_empty() { vec![1, 6, 24, 168] } else { hours };
    for h in hours {
        let inp = input(h);
        let (total, _) = check(&inp).expect("native check");
        let env = ExecutorEnv::builder().write(&inp).unwrap().build().unwrap();
        let t = Instant::now();
        if mode == "execute" {
            let s = default_executor().execute(env, bench_methods::RENT_BENCH_GUEST_ELF).unwrap();
            let (gt, _): (u64, Hash) = s.journal.decode().unwrap();
            assert_eq!(gt, total);
            println!("hours={h} cycles={} segments={} wall_s={:.2}",
                s.cycles(), s.segments.len(), t.elapsed().as_secs_f64());
        } else {
            let info = default_prover().prove(env, bench_methods::RENT_BENCH_GUEST_ELF).unwrap();
            println!("hours={h} proved: cycles={} segments={} wall_s={:.1}", info.stats.total_cycles, info.stats.segments, t.elapsed().as_secs_f64());
        }
    }
}
