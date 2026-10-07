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
