//! `sentryra-verify <evidence.jsonl> [evidence.pub hex file]`: offline check of an Edge evidence chain:
//! sequence, hash links, entry hashes and Ed25519 signatures. (Merkle checkpoints: M3.)
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let Some(path) = a.first() else {
        eprintln!("usage: sentryra-verify <evidence.jsonl|.json> [evidence.pub]");
        std::process::exit(2)
    };
    let data = std::fs::read_to_string(path).expect("read evidence");
    let entries: Vec<sentryra_evidence::Entry> = if data.trim_start().starts_with('[') {
        serde_json::from_str(&data).expect("parse")
    } else {
        data.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("parse line"))
            .collect()
    };
    let key = a.get(1).map(|p| {
        let b: [u8; 32] = hex::decode(std::fs::read_to_string(p).expect("read key").trim())
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        ed25519_dalek::VerifyingKey::from_bytes(&b).expect("key")
    });
    match sentryra_evidence::verify(&entries, key.as_ref()) {
        Ok(()) => println!(
            "OK: {} entries, hash chain intact{}; head {}",
            entries.len(),
            if key.is_some() {
                ", all signatures valid"
            } else {
                " (signatures NOT checked: no key given)"
            },
            entries.last().map(|e| &e.entry_hash[..16]).unwrap_or("-")
        ),
        Err(e) => {
            println!("FAIL: {e:?}");
            std::process::exit(1)
        }
    }
}
