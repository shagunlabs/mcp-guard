//! M1: mandate JSON -> Biscuit token; verification, attenuation, expiry and revocation IDs.
use crate::{Effect, Mandate, MandateError};
use biscuit_auth::{builder::BlockBuilder, AuthorizerBuilder, Biscuit, KeyPair, PublicKey};
use std::collections::HashSet;

/// Quote a value as a Datalog string literal (JSON string escaping is a subset Biscuit accepts).
fn q(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

fn is_rfc3339_utc(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z'
        && s.chars()
            .enumerate()
            .all(|(i, c)| [4, 7, 10, 13, 16, 19].contains(&i) || c.is_ascii_digit())
}

fn eff(e: Effect) -> &'static str {
    match e {
        Effect::Allow => "allow",
        Effect::Escalate => "escalate",
        Effect::Deny => "deny",
    }
}

#[derive(Debug)]
pub enum TokenError {
    Invalid(MandateError),
    BadTime(String),
    Biscuit(String),
    Revoked,
}
impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl From<biscuit_auth::error::Token> for TokenError {
    fn from(e: biscuit_auth::error::Token) -> Self {
        TokenError::Biscuit(e.to_string())
    }
}

/// Compile and sign a validated mandate into a Biscuit (authority block, tenant root key).
pub fn issue(m: &Mandate, root: &KeyPair) -> Result<Biscuit, TokenError> {
    m.validate().map_err(TokenError::Invalid)?;
    for t in [&m.not_before, &m.expires_at] {
        if !is_rfc3339_utc(t) {
            return Err(TokenError::BadTime(t.clone()));
        }
    }
    let principal = m
        .principal
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let agent = m
        .agent
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let mut code = format!(
        "mandate({}); tenant({}); principal({}); agent({}); purpose({});\n\
         check if time($t), $t >= {};\ncheck if time($t), $t <= {};\n",
        q(&m.mandate_id),
        q(&m.tenant),
        q(principal),
        q(agent),
        q(&m.purpose),
        m.not_before,
        m.expires_at
    );
    for s in &m.scopes {
        let c = s
            .constraints
            .as_ref()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "{}".into());
        code.push_str(&format!(
            "scope({}, {}, {}, {});\n",
            q(&s.tool),
            q(&s.resource),
            q(eff(s.effect)),
            q(&c)
        ));
    }
    Ok(Biscuit::builder().code(code)?.build(root)?)
}

/// Offline attenuation: restrict to a set of (tool, resource) pairs and/or an earlier expiry.
/// Appended blocks can only add checks, so they can only narrow.
pub fn attenuate(
    tok: &Biscuit,
    only: &[(&str, &str)],
    expires_before: Option<&str>,
) -> Result<Biscuit, TokenError> {
    let mut code = String::new();
    if !only.is_empty() {
        let alts: Vec<String> = only
            .iter()
            .map(|(t, r)| format!("tool({}), resource({})", q(t), q(r)))
            .collect();
        code.push_str(&format!("check if {};\n", alts.join(" or ")));
    }
    if let Some(e) = expires_before {
        if !is_rfc3339_utc(e) {
            return Err(TokenError::BadTime(e.into()));
        }
        code.push_str(&format!("check if time($t), $t <= {e};\n"));
    }
    Ok(tok.append(BlockBuilder::new().code(code)?)?)
}

/// Hex revocation IDs, one per block. Revoking any block's ID revokes that token and all its descendants.
pub fn revocation_ids(tok: &Biscuit) -> Vec<String> {
    tok.revocation_identifiers()
        .iter()
        .map(|v| hex::encode_upper(v))
        .collect()
}

mod hex {
    pub fn encode_upper(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}

/// Resource glob: `*` within a `/` segment, `**` across segments; everything else literal.
pub fn resource_matches(pat: &str, s: &str) -> bool {
    fn go(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) if p.get(1) == Some(&b'*') => {
                (0..=s.len()).any(|i| go(&p[2..], &s[i..]))
            }
            (Some(b'*'), _) => (0..=s.len())
                .take_while(|&i| i == 0 || s[i - 1] != b'/')
                .any(|i| go(&p[1..], &s[i..])),
            (Some(a), Some(b)) if a == b => go(&p[1..], &s[1..]),
            _ => false,
        }
    }
    go(pat.as_bytes(), s.as_bytes())
}

#[derive(Debug, Clone)]
pub struct Verified {
    pub mandate_id: String,
    pub principal: String,
    pub agent: String,
    /// The principal's purpose (trusted reference intent).
    pub purpose: String,
    /// Strictest effect among matching scopes (before constraint evaluation).
    pub effect: Effect,
    /// Every matching scope as (effect, constraints JSON). Constraints are part of the signed authority block.
    pub scopes: Vec<(Effect, serde_json::Value)>,
}

/// Verify signature, revocation, expiry and attenuation checks for one action; return the mandate effect.
/// `now` is an RFC 3339 UTC timestamp. Checks failing (expired, attenuated away) => Err; no scope => Deny.
pub fn verify(
    b64: &str,
    root: PublicKey,
    revoked: &HashSet<String>,
    tool: &str,
    resource: &str,
    now: &str,
) -> Result<Verified, TokenError> {
    if !is_rfc3339_utc(now) {
        return Err(TokenError::BadTime(now.into()));
    }
    let tok = Biscuit::from_base64(b64.trim(), root)?;
    if revocation_ids(&tok).iter().any(|id| revoked.contains(id)) {
        return Err(TokenError::Revoked);
    }
    let mut a = AuthorizerBuilder::new()
        .code(format!(
            "time({now}); tool({}); resource({}); allow if mandate($m);",
            q(tool),
            q(resource)
        ))?
        .set_limits(biscuit_auth::AuthorizerLimits {
            // default is 1 ms, which flakes under load; still bounded
            max_time: std::time::Duration::from_millis(20),
            ..Default::default()
        })
        .build(&tok)?;
    a.authorize()?;
    let one = |rule: &str, a: &mut biscuit_auth::Authorizer| -> Result<String, TokenError> {
        let v: Vec<(String,)> = a.query(rule)?;
        Ok(v.into_iter().next().map(|x| x.0).unwrap_or_default())
    };
    // Scope resources may be globs (`repo:acme/*`, `url:*`): `*` matches within one `/` segment,
    // `**` across segments. Matching happens here, over scopes from the signed authority block.
    let all: Vec<(String, String, String)> =
        a.query(format!("e($r, $e, $c) <- scope({}, $r, $e, $c)", q(tool)).as_str())?;
    let rows: Vec<(String, String)> = all
        .into_iter()
        .filter(|(r, _, _)| resource_matches(r, resource))
        .map(|(_, e, c)| (e, c))
        .collect();
    let to_eff = |e: &str| match e {
        "allow" => Effect::Allow,
        "escalate" => Effect::Escalate,
        _ => Effect::Deny,
    };
    let scopes: Vec<(Effect, serde_json::Value)> = rows
        .iter()
        .map(|(e, c)| {
            (
                to_eff(e),
                serde_json::from_str(c).unwrap_or(serde_json::Value::Null),
            )
        })
        .collect();
    let effect = scopes
        .iter()
        .map(|(e, _)| *e)
        .max_by_key(|e| match e {
            Effect::Allow => 0,
            Effect::Escalate => 1,
            Effect::Deny => 2,
        })
        .unwrap_or(Effect::Deny);
    Ok(Verified {
        mandate_id: one("m($m) <- mandate($m)", &mut a)?,
        principal: one("p($p) <- principal($p)", &mut a)?,
        agent: one("a($a) <- agent($a)", &mut a)?,
        purpose: one("p($p) <- purpose($p)", &mut a)?,
        effect,
        scopes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const EX: &str = include_str!("../../../spec/examples/mandate-v0.json");
    const NOW: &str = "2026-10-07T13:00:00Z";
    fn setup() -> (KeyPair, Biscuit) {
        let root = KeyPair::new();
        let t = issue(&Mandate::from_json(EX).unwrap(), &root).unwrap();
        (root, t)
    }
    fn v(
        t: &Biscuit,
        root: &KeyPair,
        tool: &str,
        res: &str,
        now: &str,
    ) -> Result<Verified, TokenError> {
        verify(
            &t.to_base64().unwrap(),
            root.public(),
            &HashSet::new(),
            tool,
            res,
            now,
        )
    }
    #[test]
    fn issue_and_verify_effects() {
        let (root, t) = setup();
        let r = v(&t, &root, "k8s.apply", "cluster:staging/ns:billing", NOW).unwrap();
        assert_eq!(r.effect, Effect::Allow);
        assert_eq!(r.principal, "priya@acme.com");
        let pg = v(&t, &root, "postgres.query", "db:billing", NOW).unwrap();
        assert_eq!(pg.scopes[0].1["max_rows"], 1000);
        assert_eq!(
            v(&t, &root, "k8s.apply", "cluster:prod/ns:billing", NOW)
                .unwrap()
                .effect,
            Effect::Escalate
        );
        assert_eq!(
            v(&t, &root, "k8s.delete", "cluster:prod/ns:billing", NOW)
                .unwrap()
                .effect,
            Effect::Deny
        );
    }
    #[test]
    fn resource_globs() {
        assert!(resource_matches("repo:acme/*", "repo:acme/billing"));
        assert!(!resource_matches("repo:acme/*", "repo:acme/billing/x"));
        assert!(!resource_matches("repo:acme/*", "repo:acmex/billing"));
        assert!(resource_matches("url:*", "url:api.example"));
        assert!(resource_matches("fs:/app/**", "fs:/app/a/b"));
        assert!(resource_matches("db:billing", "db:billing"));
        assert!(!resource_matches("db:billing", "db:billing2"));
    }
    #[test]
    fn wrong_root_key_rejected() {
        let (_, t) = setup();
        assert!(v(
            &t,
            &KeyPair::new(),
            "k8s.apply",
            "cluster:staging/ns:billing",
            NOW
        )
        .is_err());
    }
    #[test]
    fn expiry_and_not_before() {
        let (root, t) = setup();
        assert!(v(
            &t,
            &root,
            "k8s.apply",
            "cluster:staging/ns:billing",
            "2026-10-07T21:00:00Z"
        )
        .is_err());
        assert!(v(
            &t,
            &root,
            "k8s.apply",
            "cluster:staging/ns:billing",
            "2026-10-07T12:00:00Z"
        )
        .is_err());
    }
    #[test]
    fn attenuation_narrows_only() {
        let (root, t) = setup();
        let a = attenuate(
            &t,
            &[("postgres.query", "db:billing")],
            Some("2026-10-07T14:00:00Z"),
        )
        .unwrap();
        assert_eq!(
            v(&a, &root, "postgres.query", "db:billing", NOW)
                .unwrap()
                .effect,
            Effect::Allow
        );
        assert!(v(&a, &root, "k8s.apply", "cluster:staging/ns:billing", NOW).is_err());
        assert!(v(
            &a,
            &root,
            "postgres.query",
            "db:billing",
            "2026-10-07T15:00:00Z"
        )
        .is_err());
        // An attenuation block cannot add authority: a scope fact in a later block is not trusted.
        let sneaky = t
            .append(
                BlockBuilder::new()
                    .code(r#"scope("k8s.delete", "cluster:prod/ns:billing", "allow", "{}");"#)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            v(&sneaky, &root, "k8s.delete", "cluster:prod/ns:billing", NOW)
                .unwrap()
                .effect,
            Effect::Deny
        );
    }
    #[test]
    fn revocation() {
        let (root, t) = setup();
        let a = attenuate(&t, &[], Some("2026-10-07T14:00:00Z")).unwrap();
        let ids = revocation_ids(&a);
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], revocation_ids(&t)[0]);
        let revoked: HashSet<String> = [ids[0].clone()].into();
        // revoking the parent revokes the attenuated child
        let r = verify(
            &a.to_base64().unwrap(),
            root.public(),
            &revoked,
            "k8s.apply",
            "cluster:staging/ns:billing",
            NOW,
        );
        assert!(matches!(r, Err(TokenError::Revoked)));
    }
    #[test]
    fn tampered_token_rejected() {
        let (root, t) = setup();
        let mut b = t.to_vec().unwrap();
        let n = b.len() / 2;
        b[n] ^= 0x01;
        assert!(Biscuit::from(&b, root.public()).is_err());
    }
}
