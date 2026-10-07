//! Approval receipts: signed, single-use, bound to the exact action (`action_hash`), short TTL.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RECEIPT_TTL_MS: u64 = 10 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Receipt {
    pub spec: String,
    pub apr_id: String,
    pub decision_id: String,
    pub action_hash: String,
    pub approver: String,
    pub issued_ms: u64,
    pub expires_ms: u64,
    #[serde(default)]
    pub sig: String,
}

/// SHA-256 over canonical {mandate_id, tool, resource, args} (sorted-key JSON).
pub fn action_hash(
    mandate_id: &str,
    tool: &str,
    resource: &str,
    args: &serde_json::Value,
) -> String {
    let v = serde_json::json!({"mandate_id": mandate_id, "tool": tool, "resource": resource, "args": args});
    hex::encode(Sha256::digest(serde_json::to_vec(&v).unwrap()))
}

fn payload(r: &Receipt) -> Vec<u8> {
    let mut v = serde_json::to_value(r).unwrap();
    v.as_object_mut().unwrap().remove("sig");
    serde_json::to_vec(&v).unwrap()
}

pub fn sign(mut r: Receipt, k: &SigningKey) -> Receipt {
    r.sig = hex::encode(k.sign(&payload(&r)).to_bytes());
    r
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReceiptError {
    BadSignature,
    WrongAction,
    Expired,
    AlreadyUsed,
}

/// Checks signature, binding and expiry. Single use is enforced by the caller's consumed set.
pub fn check(
    r: &Receipt,
    k: &VerifyingKey,
    expected_action: &str,
    now_ms: u64,
) -> Result<(), ReceiptError> {
    let sig = hex::decode(&r.sig)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or(ReceiptError::BadSignature)?;
    k.verify(&payload(r), &sig)
        .map_err(|_| ReceiptError::BadSignature)?;
    if r.action_hash != expected_action {
        return Err(ReceiptError::WrongAction);
    }
    if now_ms > r.expires_ms {
        return Err(ReceiptError::Expired);
    }
    Ok(())
}
