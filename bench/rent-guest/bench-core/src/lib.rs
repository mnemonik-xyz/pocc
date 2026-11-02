//! The rent guest's per-hour work, isolated for cycle counting: for every hour
//! one usage record and one note, each a 64-byte secp256k1 signature over
//! sha256(tagged_bytes(tag, bincode(struct))); the note binds to the record by
//! the record's hash; D5 bounds the amount. This is PE-0 sections 3 and 4
//! without the batch-level checks, which are O(1) per batch.
use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

#[derive(Clone, Serialize, Deserialize)]
pub struct Scope { pub chain_id: u64, pub vault: [u8; 20], pub token: [u8; 20] }

#[derive(Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    pub scope: Scope, pub lease_id: Hash, pub first_index: u32, pub last_index: u32,
    pub window_start: u64, pub window_end: u64, pub units: u64, pub creditable: u64,
    pub assurance: u8, pub meter_spec: Hash, pub deliverable_hash: Hash,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Note {
    pub scope: Scope, pub task_id: Hash, pub deliverable_hash: Hash, pub recipient: [u8; 20],
    pub amount: u64, pub accepted: bool, pub valid_after: u64, pub valid_until: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Input {
    pub meter_key: Vec<u8>, pub acceptance_key: Vec<u8>, pub price_per_unit: u64,
    pub records: Vec<(UsageRecord, Vec<u8>)>, pub notes: Vec<(Note, Vec<u8>)>,
}

pub fn tagged_bytes<T: Serialize>(tag: &[u8], value: &T) -> Vec<u8> {
    let encoded = bincode::serialize(value).expect("typed serialization");
    let mut bytes = Vec::with_capacity(tag.len() + encoded.len() + 16);
    bytes.extend_from_slice(&(tag.len() as u64).to_le_bytes());
    bytes.extend_from_slice(tag);
    bytes.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&encoded);
    bytes
}

pub fn verify(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_sec1_bytes(key) else { return false };
    let Ok(sig) = Signature::from_slice(signature) else { return false };
    if sig.normalize_s().is_some() { return false }
    key.verify(message, &sig).is_ok()
}

/// The per-hour gates; returns the batch total and a commitment over the records.
pub fn check(input: &Input) -> Result<(u64, Hash), &'static str> {
    if input.records.len() != input.notes.len() { return Err("D1: one record per note") }
    let mut total: u64 = 0;
    let mut acc = Sha256::new();
    for ((rec, rsig), (note, nsig)) in input.records.iter().zip(&input.notes) {
        let rmsg = tagged_bytes(b"warrant/usage/v1", rec);
        if !verify(&input.meter_key, &rmsg, rsig) { return Err("D2: record signature") }
        let rhash: Hash = Sha256::digest(&rmsg).into();
        let nmsg = tagged_bytes(b"warrant/acceptance/v1", note);
        if !verify(&input.acceptance_key, &nmsg, nsig) { return Err("note signature") }
        if note.deliverable_hash != rhash { return Err("D5: note not bound to record") }
        if rec.first_index != rec.last_index { return Err("D1: range") }
        if rec.window_end - rec.window_start != 3600 { return Err("D4") }
        if rec.creditable == 0 || rec.creditable > 3600 || rec.units > rec.creditable { return Err("D8") }
        let due = rec.units.checked_mul(input.price_per_unit).ok_or("D9")?;
        if note.amount > due { return Err("D5: amount") }
        total = total.checked_add(note.amount).ok_or("D9")?;
        acc.update(rhash);
    }
    Ok((total, acc.finalize().into()))
}
