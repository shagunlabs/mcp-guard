//! `LONG_SEND_HOLD` (Tier 1, deterministic, no model): an `external_send` call in a session that
//! has seen untrusted tool output, whose outbound text could take more than one Tier 2 window,
//! escalates for human approval. Independent of hardware speed and of whether Tier 2 is enabled.
//!
//! ## Length measure and its mapping to the scorer's windows
//! The Tier 2 scorer (`tier2-prototype/scorer.py` @ 2f40cea: `WIN, STRIDE,
//! WINDOW_BUDGET = 128, 96, 4`; `windows()`) splits the outbound text into windows of
//! `WIN` = 128 tokens of its tokenizer (`onnx/tokenizer.json`, sha256 da0e7993…62a0: BERT
//! uncased WordPiece of `sentence-transformers/all-MiniLM-L6-v2`, Apache-2.0), counted with no
//! special tokens and no truncation. A text takes more than one window iff its token count
//! `L > 128`. So the threshold here is [`T2_WINDOW_TOKENS`] = 128 and a send is long iff
//! [`token_upper_bound`] of its text is > 128.
//!
//! [`token_upper_bound`] never under-counts the scorer's tokenizer:
//! * The text is split on ASCII space / `\t` / `\n` / `\r` (whitespace for the tokenizer too, so
//!   tokens never span these).
//! * A word made only of printable ASCII (0x21..=0x7E) is tokenized exactly as BERT does it:
//!   every ASCII punctuation char is its own token, each alphanumeric run is lowercased and
//!   WordPiece'd greedily (longest match first, `##` continuation) against the embedded vocab
//!   ([`VOCAB_SHA256`], the 30522 entries of `tokenizer.json` in id order). This is exact except
//!   where the tokenizer emits FEWER tokens (literal `[CLS]`-style special tokens, runs over 100
//!   chars become one `[UNK]`).
//! * Any other word counts [`NON_ASCII_CHAR_WEIGHT`] = 4 tokens per Unicode scalar. Each
//!   WordPiece token consumes at least one normalized char, and the tokenizer's normalizer
//!   (clean text, CJK split, NFD + strip accents, lowercase) turns one code point into at most 3
//!   non-space chars (Hangul syllables; brute-forced over all 1,112,064 scalars with the
//!   tokenizer's own normalizer), and NFD length is additive per code point. 4 > 3 leaves margin
//!   for future Unicode versions (the longest canonical decomposition in Unicode is 4).
//!
//! The measured text is a SUPERSET of what the scorer reads (it joins only body / text / content /
//! message / comment / subject / description): every string or number leaf of the call's
//! arguments, at any depth, except the routing `resource` and catalogue `email`-kind (recipient)
//! arguments. Joining with spaces is additive, so the bound of the superset >= the scorer's `L`.
use sentryra_connector_manifest::{ArgKind, ToolDef};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::OnceLock;

/// Tier 2 window length in scorer tokens (`scorer.py` `WIN`).
pub const T2_WINDOW_TOKENS: usize = 128;
/// Upper bound of tokens per Unicode scalar in a word that is not pure printable ASCII.
pub const NON_ASCII_CHAR_WEIGHT: usize = 4;
/// Reason code recorded on the decision.
pub const REASON_CODE: &str = "LONG_SEND_HOLD";
/// Policy id added when the hold raises an `allow` to `escalate`.
pub const POLICY_ID: &str = "long-send-hold";

const VOCAB: &str = include_str!("../assets/t2-wordpiece-vocab.txt");
/// sha256 of `assets/t2-wordpiece-vocab.txt` (= scorer `tokenizer.json` model.vocab, id order).
pub const VOCAB_SHA256: &str = "07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3";

fn vocab() -> &'static HashSet<&'static str> {
    static V: OnceLock<HashSet<&'static str>> = OnceLock::new();
    V.get_or_init(|| VOCAB.lines().collect())
}

/// Greedy longest-match-first WordPiece token count of one lowercase ASCII alphanumeric run.
fn wordpiece(run: &str) -> usize {
    let v = vocab();
    let b = run.as_bytes();
    let (mut start, mut n) = (0usize, 0usize);
    let mut buf = String::with_capacity(run.len() + 2);
    while start < b.len() {
        let mut end = b.len();
        let mut hit = false;
        while end > start {
            buf.clear();
            if start > 0 {
                buf.push_str("##");
            }
            buf.push_str(&run[start..end]);
            if v.contains(buf.as_str()) {
                hit = true;
                break;
            }
            end -= 1;
        }
        if !hit {
            return 1; // the tokenizer emits one [UNK] for the whole word
        }
        n += 1;
        start = end;
    }
    n
}

fn ascii_word(w: &str) -> usize {
    let mut n = 0;
    let mut run = String::new();
    for c in w.chars() {
        if c.is_ascii_alphanumeric() {
            run.push(c.to_ascii_lowercase());
        } else {
            // printable ASCII non-alphanumeric = BERT punctuation: one token each
            if !run.is_empty() {
                n += wordpiece(&run);
                run.clear();
            }
            n += 1;
        }
    }
    if !run.is_empty() {
        n += wordpiece(&run);
    }
    n
}

/// Upper bound on the scorer tokenizer's token count of `s` (no special tokens). Exact on words
/// of printable ASCII, `4 x chars` on any other word. See the module docs for the proof sketch.
pub fn token_upper_bound(s: &str) -> usize {
    s.split([' ', '\t', '\n', '\r'])
        .filter(|w| !w.is_empty())
        .map(|w| {
            if w.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
                ascii_word(w)
            } else {
                NON_ASCII_CHAR_WEIGHT * w.chars().count()
            }
        })
        .sum()
}

fn leaves(v: &Value, n: &mut usize) {
    match v {
        Value::String(s) => *n += token_upper_bound(s),
        Value::Number(x) => *n += token_upper_bound(&x.to_string()),
        Value::Array(a) => a.iter().for_each(|x| leaves(x, n)),
        Value::Object(o) => o.values().for_each(|x| leaves(x, n)),
        _ => {}
    }
}

/// Token upper bound of a call's outbound text: every string / number leaf of `args` except the
/// routing `resource` and `email`-kind (recipient) arguments (catalogue kind, else inferred).
pub fn outbound_tokens(args: &Value, def: Option<&ToolDef>) -> usize {
    let mut n = 0;
    if let Some(o) = args.as_object() {
        for (k, v) in o {
            let kind = def
                .map(|d| d.kind_of(k))
                .unwrap_or_else(|| ArgKind::infer(k));
            if k == "resource" || kind == ArgKind::Email {
                continue;
            }
            leaves(v, &mut n);
        }
    } else {
        leaves(args, &mut n);
    }
    n
}

/// Whether the outbound text could take more than one Tier 2 window.
pub fn is_long(tokens: usize) -> bool {
    tokens > T2_WINDOW_TOKENS
}

#[cfg(test)]
mod t {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn vocab_pinned() {
        assert_eq!(hex::encode(Sha256::digest(VOCAB.as_bytes())), VOCAB_SHA256);
        assert_eq!(VOCAB.lines().count(), 30522);
        assert!(vocab().contains("[UNK]") && vocab().contains("##s"));
    }

    #[test]
    fn known_counts() {
        // reference counts from the scorer tokenizer (tokenizers 0.23.2, add_special_tokens=False)
        assert_eq!(token_upper_bound(""), 0);
        assert_eq!(token_upper_bound("Hello, world!"), 4);
        assert_eq!(token_upper_bound("SUP-301 refund"), 6);
        assert_eq!(token_upper_bound("asha@acme.example.invalid"), 8);
        // non-ASCII words: 4 per scalar (bound, not exact; the tokenizer gives 1 and 8)
        assert_eq!(token_upper_bound("café"), 16);
        assert_eq!(token_upper_bound("한국어"), 12);
    }

    #[test]
    fn window_threshold() {
        assert!(!is_long(128));
        assert!(is_long(129));
        let w = "word ".repeat(128);
        assert_eq!(token_upper_bound(&w), 128);
        assert!(!is_long(token_upper_bound(&w)));
        assert!(is_long(token_upper_bound(&(w + "x"))));
    }

    #[test]
    fn measured_text_excludes_resource_and_recipients_only() {
        let a = serde_json::json!({"to": "a@b.example", "resource": "mailbox:support",
            "body": "hello world", "meta": {"note": ["x y", 42]}});
        // hello world (2) + x y (2) + 42 (1)
        assert_eq!(outbound_tokens(&a, None), 5);
    }

    /// The window size must match the scorer's `WIN` when the scorer is checked out next to the
    /// code repo (dev boxes); skipped elsewhere.
    #[test]
    fn window_matches_scorer_config_when_present() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../tier2-prototype/scorer.py");
        let Ok(src) = std::fs::read_to_string(&p) else {
            eprintln!("scorer.py not present; skipped");
            return;
        };
        let line = src
            .lines()
            .find(|l| l.starts_with("WIN, STRIDE, WINDOW_BUDGET ="))
            .expect("WIN line");
        let win: usize = line
            .split('=')
            .nth(1)
            .unwrap()
            .split(',')
            .next()
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(win, T2_WINDOW_TOKENS, "{line}");
    }
}
