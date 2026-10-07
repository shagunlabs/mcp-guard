//! `sentryra verify` (open source). M0: recompute a hash chain from a JSON array of evidence entries.
fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| { eprintln!("usage: sentryra-verify <evidence.json>"); std::process::exit(2) });
    let data = std::fs::read_to_string(&path).expect("read file");
    let entries: Vec<sentryra_evidence::Entry> = serde_json::from_str(&data).expect("parse entries");
    match sentryra_evidence::verify(&entries) {
        Ok(()) => println!("OK: {} entries, chain intact (checkpoint verification: M3)", entries.len()),
        Err(e) => { println!("FAIL: {e:?}"); std::process::exit(1) }
    }
}
