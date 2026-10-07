//! `sentryra-edge doctor`: onboarding bypass check. Reports variable NAMES and file PATHS only,
//! never values or file contents.
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

const NAME_PATTERNS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "CREDENTIAL",
    "AUTH",
];
const EXACT: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "KUBECONFIG",
    "DATABASE_URL",
    "PGPASSWORD",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "SLACK_BOT_TOKEN",
    "NPM_TOKEN",
    "DOCKER_AUTH_CONFIG",
    "VAULT_TOKEN",
];
// Names that match the patterns but are not credentials.
const IGNORE: &[&str] = &["SSH_AUTH_SOCK", "XAUTHORITY", "SENTRYRA_MANDATE"];

pub struct Finding {
    pub kind: &'static str,
    pub location: String,
    pub fix: &'static str,
}

pub fn scan_env(vars: impl Iterator<Item = String>) -> Vec<Finding> {
    let mut out = vec![];
    for name in vars {
        let up = name.to_uppercase();
        if IGNORE.contains(&up.as_str()) {
            continue;
        }
        let hit = EXACT.contains(&up.as_str())
            || NAME_PATTERNS.iter().any(|p| up.contains(p))
            || (up.ends_with("_URL")
                && (up.contains("DB")
                    || up.contains("DATABASE")
                    || up.contains("REDIS")
                    || up.contains("MONGO")));
        if hit {
            out.push(Finding {
                kind: "env var",
                location: name,
                fix: "remove from the agent runtime; use the Edge broker / CLI token helper",
            });
        }
    }
    out
}

pub fn scan_files(home: &std::path::Path, cwd: &std::path::Path) -> Vec<Finding> {
    let cands: &[(&str, &'static str)] = &[
        (
            ".aws/credentials",
            "AWS static keys: switch to `credential_process = sentryra-edge ...` (STS via Edge)",
        ),
        (
            ".aws/config",
            "check for credential_process/sso settings that bypass the Edge",
        ),
        (
            ".config/gh/hosts.yml",
            "gh CLI OAuth token: use the Sentryra gh token shim instead",
        ),
        (".netrc", "plaintext host credentials: delete"),
        (
            ".git-credentials",
            "git store helper plaintext tokens: delete, use the Sentryra git credential helper",
        ),
        (
            ".kube/config",
            "kubeconfig: replace user credentials with an exec plugin via the Edge",
        ),
        (
            ".docker/config.json",
            "registry auth: remove or use a credential helper scoped by the Edge",
        ),
        (".npmrc", "may contain registry tokens"),
        (".pypirc", "may contain upload tokens"),
        (
            ".config/gcloud/application_default_credentials.json",
            "GCP ADC credentials",
        ),
        (".azure/accessTokens.json", "Azure CLI tokens"),
        (".pgpass", "Postgres passwords"),
        (".ssh/id_rsa", "SSH private key"),
        (".ssh/id_ed25519", "SSH private key"),
    ];
    let mut out = vec![];
    for (rel, fix) in cands {
        let p = home.join(rel);
        if p.is_file() {
            out.push(Finding {
                kind: "file",
                location: p.display().to_string(),
                fix,
            });
        }
    }
    if let Ok(k) = std::env::var("KUBECONFIG") {
        for p in std::env::split_paths(&k) {
            if p.is_file() {
                out.push(Finding {
                    kind: "file",
                    location: p.display().to_string(),
                    fix: "kubeconfig from $KUBECONFIG",
                });
            }
        }
    }
    for f in [".env", ".env.local", ".env.production"] {
        let p = cwd.join(f);
        if p.is_file() {
            out.push(Finding {
                kind: "file",
                location: p.display().to_string(),
                fix: "dotenv file in the agent's working directory: move secrets to the broker",
            });
        }
    }
    out
}

/// Git credential helpers: report the helper *names* configured, never what they return.
pub fn scan_git(home: &std::path::Path) -> Vec<Finding> {
    let mut out = vec![];
    let r = std::process::Command::new("git")
        .args(["config", "--get-all", "credential.helper"])
        .env("HOME", home)
        .output();
    if let Ok(o) = r {
        for h in String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
        {
            let helper = h.split_whitespace().next().unwrap_or("").to_string();
            if !helper.contains("sentryra") {
                out.push(Finding {
                    kind: "git credential helper",
                    location: format!("credential.helper = {helper}"),
                    fix: "replace with the Sentryra git credential helper",
                });
            }
        }
    }
    out
}

pub fn egress_open() -> Vec<String> {
    let mut open = vec![];
    for host in [
        "1.1.1.1:443",
        "github.com:443",
        "api.openai.com:443",
        "example.com:80",
    ] {
        if let Ok(mut addrs) = host.to_socket_addrs() {
            if let Some(a) = addrs.next() {
                if TcpStream::connect_timeout(&a, Duration::from_secs(2)).is_ok() {
                    open.push(host.to_string());
                }
            }
        }
    }
    open
}

pub fn run(home: Option<PathBuf>, network: bool) -> i32 {
    let home = home
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| "/".into());
    let cwd = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let mut f = scan_env(std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()));
    f.extend(scan_files(&home, &cwd));
    f.extend(scan_git(&home));
    println!("Sentryra lockdown report (names and paths only; no values are read or printed)");
    println!("home={}  cwd={}", home.display(), cwd.display());
    println!("\n== Standing credentials: {} finding(s)", f.len());
    for x in &f {
        println!("  [{}] {}\n      fix: {}", x.kind, x.location, x.fix);
    }
    let mut score = f.len();
    println!("\n== Outbound network");
    if network {
        let open = egress_open();
        if open.is_empty() {
            println!("  egress appears restricted (no test destination reachable)");
        } else {
            score += 1;
            println!(
                "  UNRESTRICTED: reachable without the Edge: {}",
                open.join(", ")
            );
            println!("      fix: apply the reference NetworkPolicy / sandbox profile (egress only to Edge, model endpoint, allow-list)");
        }
    } else {
        println!("  skipped (--no-network)");
    }
    println!(
        "\n== Verdict: {}",
        if score == 0 {
            "LOCKED DOWN: no standing credentials found, egress restricted"
        } else {
            "NOT LOCKED DOWN: the agent could bypass the Edge (see fixes above)"
        }
    );
    if score == 0 {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn env_names_only() {
        let f = scan_env(
            [
                "GITHUB_TOKEN",
                "PATH",
                "MY_DB_URL",
                "SSH_AUTH_SOCK",
                "AWS_SECRET_ACCESS_KEY",
                "HOME",
            ]
            .iter()
            .map(|s| s.to_string()),
        );
        let names: Vec<_> = f.iter().map(|x| x.location.as_str()).collect();
        assert_eq!(
            names,
            ["GITHUB_TOKEN", "MY_DB_URL", "AWS_SECRET_ACCESS_KEY"]
        );
    }
    #[test]
    fn files_found_without_reading_values() {
        let d = std::env::temp_dir().join(format!("sentryra-doctor-{}", std::process::id()));
        std::fs::create_dir_all(d.join(".aws")).unwrap();
        std::fs::create_dir_all(d.join(".config/gh")).unwrap();
        std::fs::write(
            d.join(".aws/credentials"),
            "aws_secret_access_key = SUPERSECRET",
        )
        .unwrap();
        std::fs::write(
            d.join(".config/gh/hosts.yml"),
            "oauth_token: gho_SUPERSECRET",
        )
        .unwrap();
        std::fs::write(d.join(".netrc"), "machine x password SUPERSECRET").unwrap();
        let f = scan_files(&d, &d);
        assert_eq!(f.len(), 3);
        assert!(f
            .iter()
            .all(|x| !x.location.contains("SUPERSECRET") && !x.fix.contains("SUPERSECRET")));
        std::fs::remove_dir_all(d).ok();
    }
}
