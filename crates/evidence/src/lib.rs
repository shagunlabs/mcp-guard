//! Evidence v0: per-instance hash chain. entry_hash = SHA-256(canonical(entry) || prev_hash).
//! M0 uses serde_json with sorted keys (BTreeMap) as a stand-in for full RFC 8785 JCS; signatures and Merkle checkpoints are M3.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub seq: u64,
    pub decision_id: String,
    pub tool: String,
    pub resource: String,
    pub args_hmac: String,
    pub decision: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

fn canonical(e: &Entry) -> Vec<u8> {
    let mut v = serde_json::to_value(e).expect("serialisable");
    v.as_object_mut().unwrap().remove("entry_hash");
    // serde_json::Map is a BTreeMap without the preserve_order feature => sorted keys
    serde_json::to_vec(&v).unwrap()
}

pub fn hash_entry(e: &Entry) -> String {
    let mut h = Sha256::new();
    h.update(canonical(e));
    h.update(e.prev_hash.as_bytes());
    hex::encode(h.finalize())
}

#[derive(Default)]
pub struct Chain { pub entries: Vec<Entry> }

impl Chain {
    pub fn append(&mut self, decision_id: &str, tool: &str, resource: &str, args_hmac: &str, decision: &str) -> &Entry {
        let prev = self.entries.last().map(|e| e.entry_hash.clone()).unwrap_or_else(|| GENESIS.into());
        let mut e = Entry { seq: self.entries.len() as u64, decision_id: decision_id.into(), tool: tool.into(),
            resource: resource.into(), args_hmac: args_hmac.into(), decision: decision.into(), prev_hash: prev, entry_hash: String::new() };
        e.entry_hash = hash_entry(&e);
        self.entries.push(e);
        self.entries.last().unwrap()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError { BadSeq(u64), BrokenLink(u64), BadHash(u64) }

pub fn verify(entries: &[Entry]) -> Result<(), VerifyError> {
    let mut prev = GENESIS.to_string();
    for (i, e) in entries.iter().enumerate() {
        if e.seq != i as u64 { return Err(VerifyError::BadSeq(e.seq)); }
        if e.prev_hash != prev { return Err(VerifyError::BrokenLink(e.seq)); }
        if hash_entry(e) != e.entry_hash { return Err(VerifyError::BadHash(e.seq)); }
        prev = e.entry_hash.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn chain() -> Chain { let mut c = Chain::default(); for i in 0..5 { c.append(&format!("d{i}"), "k8s.apply", "cluster:staging", "h", "allow"); } c }
    #[test] fn valid() { assert!(verify(&chain().entries).is_ok()); }
    #[test] fn tamper() { let mut c = chain(); c.entries[2].decision = "deny".into(); assert_eq!(verify(&c.entries), Err(VerifyError::BadHash(2))); }
    #[test] fn deletion() { let mut c = chain(); c.entries.remove(2); assert!(verify(&c.entries).is_err()); }
    // Truncation of the tail is NOT detectable by a chain alone: that is what M3 signed checkpoints are for.
    #[test] fn tail_truncation_needs_checkpoints() { let mut c = chain(); c.entries.pop(); assert!(verify(&c.entries).is_ok()); }
}
