//! Evidence v0: per-instance, signed hash chain.
//!
//! * `entry_hash = SHA-256(canonical(entry without entry_hash/sig) || prev_hash)`
//! * Personal or payload-bearing fields (arguments, principal) are **never** stored raw: they are
//!   recorded as `HMAC-SHA256(tenant_salt_key, canonical(value))`, so the chain hash covers only
//!   salted hashes. Salted hashes of personal data are still treated as personal data (see spec §11).
//! * Each entry is signed with the Edge instance Ed25519 key over `entry_hash`.
//! * Canonical form: serde_json with sorted keys (stand-in for RFC 8785 JCS).
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub v: u32,
    pub seq: u64,
    pub ts_ms: u64,
    pub decision_id: String,
    pub mandate_id: String,
    pub tool: String,
    pub resource: String,
    /// HMAC of canonical arguments. Raw arguments never enter the chain.
    pub args_hmac: String,
    /// HMAC of the principal identifier.
    pub principal_hmac: String,
    pub tainted: bool,
    /// allow | escalate | deny
    pub decision: String,
    /// shadow | enforce
    pub mode: String,
    pub enforced: bool,
    pub policy_ids: Vec<String>,
    pub reasons: Vec<String>,
    pub prev_hash: String,
    #[serde(default)]
    pub entry_hash: String,
    #[serde(default)]
    pub sig: String,
}

/// Fields of an entry before it is chained.
pub struct NewEntry<'a> {
    pub ts_ms: u64,
    pub decision_id: &'a str,
    pub mandate_id: &'a str,
    pub tool: &'a str,
    pub resource: &'a str,
    pub args: &'a serde_json::Value,
    pub principal: &'a str,
    pub tainted: bool,
    pub decision: &'a str,
    pub mode: &'a str,
    pub enforced: bool,
    pub policy_ids: Vec<String>,
    pub reasons: Vec<String>,
}

pub fn salted_hash(key: &[u8], value: &serde_json::Value) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
    m.update(&serde_json::to_vec(value).unwrap());
    hex::encode(m.finalize().into_bytes())
}

fn canonical(e: &Entry) -> Vec<u8> {
    let mut v = serde_json::to_value(e).expect("serialisable");
    let o = v.as_object_mut().unwrap();
    o.remove("entry_hash");
    o.remove("sig");
    serde_json::to_vec(&v).unwrap()
}

pub fn hash_entry(e: &Entry) -> String {
    let mut h = Sha256::new();
    h.update(canonical(e));
    h.update(e.prev_hash.as_bytes());
    hex::encode(h.finalize())
}

pub struct Chain {
    pub entries: Vec<Entry>,
    signing: SigningKey,
    salt_key: Vec<u8>,
}

impl Chain {
    pub fn new(signing: SigningKey, salt_key: Vec<u8>) -> Self {
        Self {
            entries: vec![],
            signing,
            salt_key,
        }
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
    pub fn append(&mut self, n: NewEntry) -> &Entry {
        let prev = self
            .entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| GENESIS.into());
        let mut e = Entry {
            v: 0,
            seq: self.entries.len() as u64,
            ts_ms: n.ts_ms,
            decision_id: n.decision_id.into(),
            mandate_id: n.mandate_id.into(),
            tool: n.tool.into(),
            resource: n.resource.into(),
            args_hmac: salted_hash(&self.salt_key, n.args),
            principal_hmac: salted_hash(
                &self.salt_key,
                &serde_json::Value::String(n.principal.into()),
            ),
            tainted: n.tainted,
            decision: n.decision.into(),
            mode: n.mode.into(),
            enforced: n.enforced,
            policy_ids: n.policy_ids,
            reasons: n.reasons,
            prev_hash: prev,
            entry_hash: String::new(),
            sig: String::new(),
        };
        e.entry_hash = hash_entry(&e);
        e.sig = hex::encode(self.signing.sign(e.entry_hash.as_bytes()).to_bytes());
        self.entries.push(e);
        self.entries.last().unwrap()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    BadSeq(u64),
    BrokenLink(u64),
    BadHash(u64),
    BadSignature(u64),
}

pub fn verify(entries: &[Entry], key: Option<&VerifyingKey>) -> Result<(), VerifyError> {
    let mut prev = GENESIS.to_string();
    for (i, e) in entries.iter().enumerate() {
        if e.seq != i as u64 {
            return Err(VerifyError::BadSeq(e.seq));
        }
        if e.prev_hash != prev {
            return Err(VerifyError::BrokenLink(e.seq));
        }
        if hash_entry(e) != e.entry_hash {
            return Err(VerifyError::BadHash(e.seq));
        }
        if let Some(k) = key {
            let ok = hex::decode(&e.sig)
                .ok()
                .and_then(|b| Signature::from_slice(&b).ok())
                .map(|s| k.verify(e.entry_hash.as_bytes(), &s).is_ok())
                .unwrap_or(false);
            if !ok {
                return Err(VerifyError::BadSignature(e.seq));
            }
        }
        prev = e.entry_hash.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn chain() -> Chain {
        let mut c = Chain::new(
            SigningKey::generate(&mut rand::rngs::OsRng),
            b"salt".to_vec(),
        );
        for i in 0..5 {
            let args = serde_json::json!({"sql": format!("SELECT {i}")});
            c.append(NewEntry {
                ts_ms: i,
                decision_id: &format!("d{i}"),
                mandate_id: "m",
                tool: "db.query",
                resource: "db:demo",
                args: &args,
                principal: "priya@acme.com",
                tainted: false,
                decision: "allow",
                mode: "enforce",
                enforced: true,
                policy_ids: vec![],
                reasons: vec![],
            });
        }
        c
    }
    #[test]
    fn valid_and_signed() {
        let c = chain();
        assert!(verify(&c.entries, Some(&c.verifying_key())).is_ok());
    }
    #[test]
    fn tamper() {
        let mut c = chain();
        c.entries[2].decision = "deny".into();
        assert_eq!(verify(&c.entries, None), Err(VerifyError::BadHash(2)));
    }
    #[test]
    fn resigned_with_other_key_fails() {
        let mut c = chain();
        let k = c.verifying_key();
        let other = SigningKey::generate(&mut rand::rngs::OsRng);
        c.entries[1].sig = hex::encode(other.sign(c.entries[1].entry_hash.as_bytes()).to_bytes());
        assert_eq!(
            verify(&c.entries, Some(&k)),
            Err(VerifyError::BadSignature(1))
        );
    }
    #[test]
    fn deletion() {
        let mut c = chain();
        c.entries.remove(2);
        assert!(verify(&c.entries, None).is_err());
    }
    #[test]
    fn no_raw_values_in_entries() {
        let c = chain();
        let s = serde_json::to_string(&c.entries).unwrap();
        assert!(!s.contains("priya") && !s.contains("SELECT"));
    }
    // Tail truncation is NOT detectable by a chain alone: M3 signed checkpoints close that.
    #[test]
    fn tail_truncation_needs_checkpoints() {
        let mut c = chain();
        c.entries.pop();
        assert!(verify(&c.entries, None).is_ok());
    }
}
