//! Used approval-receipt ids, persisted so single use survives an Edge restart.
//!
//! Append-only JSON lines `{"apr_id": "...", "expires_ms": N}` next to the evidence log
//! (`<evidence>.consumed-receipts`, mode 0600). Loaded on start; entries past receipt expiry plus
//! `MARGIN_MS` are dropped (such a receipt is refused as expired anyway) and the file is compacted.
use crate::receipts::Receipt;
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

pub const MARGIN_MS: u64 = 5 * 60 * 1000;

#[derive(serde::Serialize, serde::Deserialize)]
struct Line {
    apr_id: String,
    expires_ms: u64,
}

pub fn path_for(evidence: &Path) -> PathBuf {
    let mut s = evidence.as_os_str().to_owned();
    s.push(".consumed-receipts");
    PathBuf::from(s)
}

fn opts() -> std::fs::OpenOptions {
    let mut o = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}

/// Load live entries, rewrite the file with only those, and open it for appending.
pub fn open(
    path: &Path,
    now_ms: u64,
) -> std::io::Result<(HashMap<String, u64>, Option<std::fs::File>)> {
    let mut m = HashMap::new();
    match std::fs::File::open(path) {
        Ok(f) => {
            for l in std::io::BufReader::new(f).lines() {
                // A torn last line was never acknowledged (the use was refused), so skipping it is safe.
                if let Ok(x) = serde_json::from_str::<Line>(&l?) {
                    if x.expires_ms.saturating_add(MARGIN_MS) >= now_ms {
                        m.insert(x.apr_id, x.expires_ms);
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let tmp = {
        let mut s = path.as_os_str().to_owned();
        s.push(".tmp");
        PathBuf::from(s)
    };
    {
        let mut f = opts().create(true).write(true).truncate(true).open(&tmp)?;
        for (id, exp) in &m {
            writeln!(f, "{}", line(id, *exp))?;
        }
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    let f = opts().append(true).open(path)?;
    Ok((m, Some(f)))
}

fn line(id: &str, exp: u64) -> String {
    serde_json::to_string(&Line {
        apr_id: id.into(),
        expires_ms: exp,
    })
    .unwrap()
}

/// Durably record `r` as used (file first, then memory). Err => the caller must refuse the receipt.
pub fn record(
    m: &mut HashMap<String, u64>,
    f: Option<&mut std::fs::File>,
    r: &Receipt,
    now_ms: u64,
) -> std::io::Result<()> {
    if let Some(f) = f {
        writeln!(f, "{}", line(&r.apr_id, r.expires_ms))?;
        f.flush()?;
        f.sync_data()?;
    }
    m.insert(r.apr_id.clone(), r.expires_ms);
    if m.len() > 10_000 {
        m.retain(|_, exp| exp.saturating_add(MARGIN_MS) >= now_ms);
    }
    Ok(())
}
