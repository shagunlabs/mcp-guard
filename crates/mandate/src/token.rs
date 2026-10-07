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
        code.push_str(&format!(
            "scope({}, {}, {});\n",
            q(&s.tool),
            q(&s.resource),
            q(eff(s.effect))
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

#[derive(Debug, Clone)]
pub struct Verified {
    pub mandate_id: String,
    pub principal: String,
    pub agent: String,
    pub effect: Effect,
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
        .build(&tok)?;
    a.authorize()?;
    let one = |rule: &str, a: &mut biscuit_auth::Authorizer| -> Result<String, TokenError> {
        let v: Vec<(String,)> = a.query(rule)?;
        Ok(v.into_iter().next().map(|x| x.0).unwrap_or_default())
    };
    let effects: Vec<(String,)> =
        a.query(format!("e($e) <- scope({}, {}, $e)", q(tool), q(resource)).as_str())?;
    let effect = effects
        .iter()
        .map(|(e,)| match e.as_str() {
            "allow" => Effect::Allow,
            "escalate" => Effect::Escalate,
            _ => Effect::Deny,
        })
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
        effect,
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
                    .code(r#"scope("k8s.delete", "cluster:prod/ns:billing", "allow");"#)
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
