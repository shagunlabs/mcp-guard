//! Taint tracking over relayed untrusted tool outputs (design: the research typed-sink approach).
//!
//! * **Typed sinks** (table, recipient/email, branch, amount, host, path, channel, group, user, id,
//!   cmd tokens, SQL identifiers/literals, URL host/path/query values): **exact normalised matching
//!   against atoms extracted from untrusted output, no length minimum.**
//! * **Free-text sinks** (`text` kind, or untyped values containing spaces): fuzzy fingerprints with
//!   a minimum length and entropy (atoms >= 12 chars, 3–4-word shingles >= 16 chars, >= 3.0 bits/char).
//! * URLs are parsed into host, path and query (keys and values) before fingerprinting and matching.
//! * Outbound argument values go through decoding passes (URL-encoding, base64, hex; up to two
//!   levels) before matching.
//! * Atoms that also appear in the trusted mandate `purpose` don't count (user overlap).
use base64::Engine as _;
use sentryra_connector_manifest::ArgKind;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const MIN_ATOM_LEN: usize = 12;
pub const MIN_SHINGLE_LEN: usize = 16;
pub const MIN_ENTROPY_BITS: f64 = 3.0;

#[derive(Default)]
pub struct Store {
    atoms: HashSet<String>,
    fps: HashSet<[u8; 16]>,
}

fn h(s: &str) -> [u8; 16] {
    let d = Sha256::digest(s.as_bytes());
    let mut o = [0u8; 16];
    o.copy_from_slice(&d[..16]);
    o
}

pub fn entropy(s: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    let n = s.chars().count() as f64;
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn norm(s: &str) -> String {
    s.trim()
        .trim_matches(|c: char| ".,;:!?\"'`()[]{}<>".contains(c))
        .to_lowercase()
}

/// Canonical number form ("40.00" -> "40", "4017.330" -> "4017.33").
pub fn num(s: &str) -> Option<String> {
    let x: f64 = s.trim().parse().ok()?;
    if !x.is_finite() {
        return None;
    }
    let mut t = format!("{x:.6}");
    while t.contains('.') && (t.ends_with('0') || t.ends_with('.')) {
        t.pop();
    }
    Some(format!("num:{t}"))
}

pub fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16)
                {
                    Ok(v) => {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parsed URL parts: host, full path, each path segment, query keys and values.
pub fn url_parts(u: &str) -> Option<Vec<String>> {
    let (_, rest) = u.split_once("://")?;
    let (auth, tail) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let host = auth.rsplit_once('@').map(|(_, h)| h).unwrap_or(auth);
    let host = host.split(':').next().unwrap_or("").to_lowercase();
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, q.split('#').next().unwrap_or("")),
        None => (tail.split('#').next().unwrap_or(""), ""),
    };
    let mut out = vec![format!("host:{host}")];
    if !path.is_empty() && path != "/" {
        out.push(url_decode(path).to_lowercase());
    }
    for kv in query.split('&').filter(|x| !x.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        out.push(url_decode(k).to_lowercase());
        if !v.is_empty() {
            out.push(url_decode(v).to_lowercase());
        }
    }
    Some(out)
}

fn printable(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t')
}

/// The value plus decodings (URL, base64 std/url-safe, hex), up to two levels deep.
pub fn decodings(v: &str) -> Vec<String> {
    fn one(s: &str) -> Vec<String> {
        let mut out = vec![];
        if s.contains('%') {
            let d = url_decode(s);
            if d != s {
                out.push(d);
            }
        }
        let t = s.trim();
        if t.len() >= 8
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=-_".contains(c))
        {
            for eng in [
                &base64::engine::general_purpose::STANDARD,
                &base64::engine::general_purpose::URL_SAFE,
            ] {
                if let Ok(b) = eng.decode(t) {
                    if let Ok(x) = String::from_utf8(b) {
                        if printable(&x) {
                            out.push(x);
                        }
                    }
                }
            }
            if t.len().is_multiple_of(2) && t.chars().all(|c| c.is_ascii_hexdigit()) {
                let b: Option<Vec<u8>> = (0..t.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&t[i..i + 2], 16).ok())
                    .collect();
                if let Some(x) = b.and_then(|b| String::from_utf8(b).ok()) {
                    if printable(&x) {
                        out.push(x);
                    }
                }
            }
        }
        out
    }
    let mut all = vec![v.to_string()];
    let lvl1 = one(v);
    for d in &lvl1 {
        all.extend(one(d));
    }
    all.extend(lvl1);
    all.sort();
    all.dedup();
    all
}

fn split_tokens(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c.is_whitespace() || "\"'`()[]{},;<>|".contains(c))
        .filter(|t| !t.is_empty())
}

/// Atoms extracted from text (used for both outputs and the trusted purpose).
pub fn atoms_of(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for tok in split_tokens(text) {
        let n = norm(tok);
        if n.is_empty() {
            continue;
        }
        if let Some(parts) = url_parts(&n) {
            out.extend(parts);
        }
        if let Some((_, d)) = n.rsplit_once('@') {
            out.insert(format!("host:{d}"));
        }
        if let Some(x) = num(&n) {
            out.insert(x);
        }
        // path-like tokens: every suffix at a segment boundary, so typed Path args match exactly
        if tok.contains('/') && !tok.contains("://") {
            let segs: Vec<&str> = tok.split('/').filter(|x| !x.is_empty()).collect();
            for i in 0..segs.len() {
                out.insert(segs[i..].join("/").to_lowercase());
            }
        }
        // a bare hostname in prose ("send it to collector.example") is a host atom too
        if looks_like_host(&n) {
            out.insert(format!("host:{n}"));
        }
        // `key=value` and `a:b` pieces too (e.g. "--token=$x", "branch:foo")
        for piece in n.split(['=', ':']) {
            let p = norm(piece);
            if !p.is_empty() && p != n {
                out.insert(p);
            }
        }
        out.insert(n);
    }
    out
}

fn looks_like_host(n: &str) -> bool {
    n.contains('.')
        && !n.contains("..")
        && n.split('.').count() >= 2
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && n.chars().any(|c| c.is_ascii_alphabetic())
        && num(n).is_none()
}

fn words(s: &str) -> Vec<String> {
    s.split(|c: char| !(c.is_alphanumeric() || "@._-:/".contains(c)))
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect()
}

fn fingerprints(s: &str) -> Vec<[u8; 16]> {
    let w = words(s);
    let mut out = vec![];
    for x in &w {
        if x.chars().count() >= MIN_ATOM_LEN && entropy(x) >= MIN_ENTROPY_BITS {
            out.push(h(&format!("a:{x}")));
        }
    }
    for n in [3, 4] {
        for win in w.windows(n) {
            let j = win.join(" ");
            if j.chars().count() >= MIN_SHINGLE_LEN && entropy(&j) >= MIN_ENTROPY_BITS {
                out.push(h(&format!("s{n}:{j}")));
            }
        }
    }
    out
}

/// Candidate typed values of an argument, normalised for its kind.
fn typed_candidates(kind: ArgKind, v: &str) -> Vec<String> {
    let n = norm(v);
    match kind {
        ArgKind::Url => url_parts(&n).unwrap_or_else(|| vec![n]),
        ArgKind::Email => {
            let mut c = vec![n.clone()];
            if let Some((_, d)) = n.rsplit_once('@') {
                c.push(format!("host:{d}"));
            }
            c
        }
        ArgKind::Host => vec![format!("host:{n}"), n],
        ArgKind::Amount => num(&n).into_iter().collect(),
        ArgKind::Sql => {
            // Table names (the caller drops tables the mandate allows via `sql.tables`) plus
            // string and number literals. Columns and other identifiers are not taint-checked.
            let mut c: Vec<String> = crate::sql::tables(v);
            c.extend(
                v.split(|ch: char| !(ch.is_ascii_digit() || ch == '.' || ch == '-'))
                    .filter_map(num)
                    // 0..=99 (LIMIT 1, id = 1, ...) carry no provenance signal inside a statement
                    .filter(|n| {
                        let n = n.trim_start_matches("num:");
                        n.contains('.')
                            || n.parse::<f64>()
                                .map_or(true, |x| !(0.0..100.0).contains(&x))
                    }),
            );
            // string literals
            let mut rest = v;
            while let Some(i) = rest.find('\'') {
                let r = &rest[i + 1..];
                match r.find('\'') {
                    Some(j) => {
                        c.push(norm(&r[..j]));
                        rest = &r[j + 1..];
                    }
                    None => break,
                }
            }
            c
        }
        // Shell variable sigils (`$X`, `${X}`) are stripped so `$FAKE_TOKEN` matches `FAKE_TOKEN`.
        ArgKind::Cmd => split_tokens(&v.replace(['$', '{', '}'], " "))
            .skip(1)
            .flat_map(|t| atoms_of(t).into_iter())
            .collect(),
        // Every path suffix at a segment boundary ("/app/docs/../../etc/x" -> "../../etc/x", "etc/x", "x").
        ArgKind::Path => {
            let segs: Vec<&str> = n.split('/').filter(|x| !x.is_empty()).collect();
            let mut c: Vec<String> = (0..segs.len()).map(|i| segs[i..].join("/")).collect();
            c.push(n);
            c
        }
        _ => vec![n],
    }
}

impl Store {
    pub fn ingest(&mut self, text: &str) {
        self.atoms.extend(atoms_of(text));
        self.fps.extend(fingerprints(text));
    }
    /// Is `value` (an argument of `kind`) derived from untrusted output? `trusted` atoms (from the
    /// mandate purpose) are excluded.
    pub fn is_tainted(&self, kind: ArgKind, value: &str, trusted: &HashSet<String>) -> bool {
        let free =
            kind.is_free_text() || (matches!(kind, ArgKind::Other) && value.trim().contains(' '));
        for cand in decodings(value) {
            if free {
                // Text the principal supplied in the purpose is trusted: drop those tokens first.
                let own: String = split_tokens(&cand)
                    .filter(|t| !trusted.contains(&norm(t)))
                    .collect::<Vec<_>>()
                    .join(" ");
                if fingerprints(&own).iter().any(|f| self.fps.contains(f)) {
                    return true;
                }
                // URLs embedded in free text are still parsed and matched exactly on host/query values
                for tok in split_tokens(&cand) {
                    if let Some(parts) = url_parts(&norm(tok)) {
                        if parts
                            .iter()
                            .any(|p| self.atoms.contains(p) && !trusted.contains(p))
                        {
                            return true;
                        }
                    }
                }
            } else if typed_candidates(kind, &cand)
                .iter()
                .any(|c| !c.is_empty() && self.atoms.contains(c) && !trusted.contains(c))
            {
                return true;
            }
        }
        false
    }
    pub fn is_empty(&self) -> bool {
        self.atoms.is_empty() && self.fps.is_empty()
    }
}

#[cfg(test)]
mod t {
    use super::*;
    fn none() -> HashSet<String> {
        HashSet::new()
    }
    #[test]
    fn typed_exact_no_minimum() {
        let mut s = Store::default();
        s.ingest(
            "<UNTRUSTED: inert fixture text; marker orders_zx91> and ceo_ab92, amount 4017.330",
        );
        assert!(s.is_tainted(ArgKind::Table, "orders_zx91", &none()));
        assert!(s.is_tainted(ArgKind::Sql, "DROP TABLE orders_zx91", &none()));
        assert!(s.is_tainted(ArgKind::User, "CEO_AB92", &none()));
        assert!(s.is_tainted(ArgKind::Amount, "4017.33", &none()));
        assert!(!s.is_tainted(ArgKind::Table, "orders", &none()));
        assert!(!s.is_tainted(ArgKind::Amount, "40", &none()));
    }
    #[test]
    fn urls_parsed() {
        let mut s = Store::default();
        s.ingest("see https://collector-ye13.example.invalid/x?d=1");
        assert!(s.is_tainted(
            ArgKind::Url,
            "https://collector-ye13.example.invalid/?d=secret",
            &none()
        ));
        assert!(s.is_tainted(ArgKind::Host, "collector-ye13.example.invalid", &none()));
        assert!(!s.is_tainted(ArgKind::Url, "https://pricing.example.invalid/", &none()));
    }
    #[test]
    fn bare_host_in_prose_taints_url_host() {
        let mut s = Store::default();
        s.ingest("<UNTRUSTED: inert fixture text; marker collector-ye13.example.invalid>");
        assert!(s.is_tainted(
            ArgKind::Url,
            "https://collector-ye13.example.invalid/?d=x",
            &none()
        ));
    }
    #[test]
    fn cmd_sigils_paths_and_sql_identifiers() {
        let mut s = Store::default();
        s.ingest("marker FAKE_TOKEN_lu81 ../../etc/fake_secrets_ow12 audit_log_pm44");
        assert!(s.is_tainted(ArgKind::Cmd, "pytest --token=$FAKE_TOKEN_lu81", &none()));
        assert!(s.is_tainted(
            ArgKind::Path,
            "/app/docs/../../etc/fake_secrets_ow12",
            &none()
        ));
        assert!(s.is_tainted(ArgKind::Sql, "SELECT 1; TRUNCATE audit_log_pm44", &none()));
        assert!(!s.is_tainted(ArgKind::Sql, "SELECT count(*) FROM orders", &none()));
        // columns are not checked; literals are
        s.ingest("customer note: lifetime_value_x9 and code 'promo_zz71' and 4017.33");
        assert!(!s.is_tainted(
            ArgKind::Sql,
            "SELECT lifetime_value_x9 FROM orders",
            &none()
        ));
        assert!(s.is_tainted(
            ArgKind::Sql,
            "SELECT * FROM orders WHERE code = 'promo_zz71'",
            &none()
        ));
        assert!(s.is_tainted(
            ArgKind::Sql,
            "SELECT * FROM orders WHERE total = 4017.330",
            &none()
        ));
    }
    #[test]
    fn decoding_passes() {
        let mut s = Store::default();
        s.ingest("token FAKE_SECRET_qa57 here");
        // base64("FAKE_SECRET_qa57")
        assert!(s.is_tainted(ArgKind::Text, "RkFLRV9TRUNSRVRfcWE1Nw==", &none()));
        // hex("FAKE_SECRET_qa57")
        assert!(s.is_tainted(ArgKind::Id, "46414b455f5345435245545f71613537", &none()));
        assert!(s.is_tainted(ArgKind::Id, "FAKE%5FSECRET%5Fqa57", &none()));
    }
    #[test]
    fn free_text_keeps_minimums_and_trusted_excluded() {
        let mut s = Store::default();
        s.ingest("yes ok thanks. id 42. marker tmp_import_vb03");
        assert!(!s.is_tainted(ArgKind::Text, "ok thanks", &none()));
        assert!(!s.is_tainted(ArgKind::Text, "yes", &none()));
        let trusted = atoms_of("Clean up tmp_import_vb03 as requested");
        assert!(!s.is_tainted(ArgKind::Table, "tmp_import_vb03", &trusted));
        assert!(s.is_tainted(ArgKind::Table, "tmp_import_vb03", &none()));
    }
}
