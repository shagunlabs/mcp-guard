//! Model allowlist by sha256. The pinned copy (`model-allowlist.sha256`) holds exactly the INT8
//! digest of the cleared INT8 model. Anything else is refused before load.
use sha2::{Digest, Sha256};
use std::path::Path;

pub const PINNED: &str = include_str!("../model-allowlist.sha256");

#[derive(Debug, PartialEq, Eq)]
pub enum AllowlistError {
    Io(String),
    NotAllowed { got: String },
    BadAllowlist(String),
}

pub fn parse(text: &str) -> Result<Vec<String>, AllowlistError> {
    let v: Vec<String> = text
        .lines()
        .map(|l| {
            l.split('#')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .filter(|l| !l.is_empty())
        .collect();
    if v.is_empty()
        || v.iter()
            .any(|h| h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(AllowlistError::BadAllowlist(format!("{v:?}")));
    }
    Ok(v)
}

pub fn sha256_file(p: &Path) -> Result<String, AllowlistError> {
    let b = std::fs::read(p).map_err(|e| AllowlistError::Io(format!("{}: {e}", p.display())))?;
    Ok(hex::encode(Sha256::digest(&b)))
}

/// Refuse to load any model whose sha256 is not on the allowlist. Returns the digest.
pub fn verify(model: &Path, allow: &[String]) -> Result<String, AllowlistError> {
    let got = sha256_file(model)?;
    if allow.contains(&got) {
        Ok(got)
    } else {
        Err(AllowlistError::NotAllowed { got })
    }
}

#[cfg(test)]
mod t {
    use super::*;
    const INT8: &str = "7304e205d537eff13b20c2d104e4d6664b7a603945fdcc5909f3817bdaf20a05";
    #[test]
    fn pinned_is_exactly_the_int8_hash() {
        assert_eq!(parse(PINNED).unwrap(), vec![INT8.to_string()]);
    }
    #[test]
    fn refuses_other_files() {
        let d = std::env::temp_dir().join(format!("t2allow{}", std::process::id()));
        std::fs::write(&d, b"not the model").unwrap();
        assert!(matches!(
            verify(&d, &parse(PINNED).unwrap()),
            Err(AllowlistError::NotAllowed { .. })
        ));
        let _ = std::fs::remove_file(&d);
        assert!(parse("abc").is_err() && parse("").is_err());
    }
}
