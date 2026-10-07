use sqlparser::ast::Statement;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

#[derive(Debug, Default, Clone)]
pub struct Class {
    pub is_sql: bool,
    pub has_ddl: bool,
    pub has_dml: bool,
    pub parse_error: bool,
    pub kinds: Vec<String>,
}

/// Parse SQL and classify every statement. Anything other than a query or INSERT/UPDATE/DELETE
/// (DROP, ALTER, CREATE, TRUNCATE, GRANT, PRAGMA, ATTACH, ...) is treated as DDL.
pub fn classify(sql: &str) -> Class {
    let mut c = Class {
        is_sql: true,
        ..Default::default()
    };
    match Parser::parse_sql(&GenericDialect {}, sql) {
        Ok(stmts) if !stmts.is_empty() => {
            for s in stmts {
                let k = match &s {
                    Statement::Query(_) => "SELECT",
                    Statement::Insert(_) => "INSERT",
                    Statement::Update { .. } => "UPDATE",
                    Statement::Delete(_) => "DELETE",
                    _ => "DDL",
                };
                match k {
                    "SELECT" => {}
                    "DDL" => {
                        c.has_ddl = true;
                        let first = s
                            .to_string()
                            .split_whitespace()
                            .take(2)
                            .collect::<Vec<_>>()
                            .join(" ");
                        c.kinds.push(first);
                        continue;
                    }
                    _ => c.has_dml = true,
                }
                c.kinds.push(k.into());
            }
        }
        _ => c.parse_error = true,
    }
    // Nested statements (e.g. `WITH x AS (DELETE ... RETURNING id) SELECT ...`): scan keyword
    // tokens (string literals and comments are separate tokens, so they don't count).
    if let Ok(toks) = sqlparser::tokenizer::Tokenizer::new(&GenericDialect {}, sql).tokenize() {
        use sqlparser::keywords::Keyword as K;
        for t in toks {
            if let sqlparser::tokenizer::Token::Word(w) = t {
                match w.keyword {
                    K::DELETE | K::UPDATE | K::INSERT | K::MERGE if !c.has_dml => {
                        c.has_dml = true;
                        c.kinds.push(format!("nested {}", w.value.to_uppercase()));
                    }
                    K::DROP | K::TRUNCATE | K::ALTER | K::GRANT | K::REVOKE | K::ATTACH
                        if !c.has_ddl =>
                    {
                        c.has_ddl = true;
                        c.kinds.push(format!("nested {}", w.value.to_uppercase()));
                    }
                    _ => {}
                }
            }
        }
    }
    c
}

impl Class {
    /// Statement classes present: SELECT, INSERT, UPDATE, DELETE, MERGE, DDL.
    pub fn classes(&self) -> Vec<String> {
        let mut out = vec![];
        if self.has_ddl {
            out.push("DDL".to_string());
        }
        for k in ["SELECT", "INSERT", "UPDATE", "DELETE", "MERGE"] {
            if self
                .kinds
                .iter()
                .any(|x| x == k || x == &format!("nested {k}"))
            {
                out.push(k.to_string());
            }
        }
        out
    }
}

impl Class {
    /// DDL verbs present (DROP, TRUNCATE, ALTER, CREATE, GRANT, ...).
    pub fn ddl_verbs(&self) -> Vec<String> {
        self.kinds
            .iter()
            .filter(|k| {
                !["SELECT", "INSERT", "UPDATE", "DELETE", "MERGE"].contains(&k.as_str())
                    && !k.starts_with("nested INSERT")
                    && !k.starts_with("nested UPDATE")
                    && !k.starts_with("nested DELETE")
                    && !k.starts_with("nested MERGE")
            })
            .map(|k| {
                k.trim_start_matches("nested ")
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_uppercase()
            })
            .collect()
    }
}

/// Table names referenced after FROM / JOIN / INTO / UPDATE / TABLE (lower-case, unqualified).
pub fn tables(sql: &str) -> Vec<String> {
    use sqlparser::keywords::Keyword as K;
    use sqlparser::tokenizer::{Token, Tokenizer};
    let Ok(toks) = Tokenizer::new(&GenericDialect {}, sql).tokenize() else {
        return vec!["<unparseable>".into()];
    };
    let toks: Vec<Token> = toks
        .into_iter()
        .filter(|t| !matches!(t, Token::Whitespace(_)))
        .collect();
    let mut out = vec![];
    for (i, t) in toks.iter().enumerate() {
        if let Token::Word(w) = t {
            if matches!(
                w.keyword,
                K::FROM | K::JOIN | K::INTO | K::UPDATE | K::TABLE | K::TRUNCATE
            ) {
                if let Some(Token::Word(n)) = toks.get(i + 1) {
                    if !matches!(
                        n.keyword,
                        K::SELECT | K::LATERAL | K::IF | K::ONLY | K::UNNEST | K::VALUES
                    ) {
                        let mut name = n.value.to_lowercase();
                        if let (Some(Token::Period), Some(Token::Word(m))) =
                            (toks.get(i + 2), toks.get(i + 3))
                        {
                            name = m.value.to_lowercase();
                        }
                        out.push(name);
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn kinds() {
        assert!(!classify("SELECT * FROM users").has_ddl);
        assert!(classify("DROP TABLE users").has_ddl);
        assert!(classify("select 1; drop table users").has_ddl);
        assert!(classify("UPDATE users SET a=1").has_dml);
        assert!(classify("TRUNCATE TABLE users").has_ddl);
        assert!(classify("DROP/**/TABLE users").has_ddl);
        assert!(classify("this is not sql").parse_error);
        assert!(
            classify("WITH x AS (DELETE FROM orders RETURNING id) SELECT count(*) FROM x").has_dml
        );
        assert!(!classify("SELECT 'drop table' AS note").has_ddl);
    }
}
