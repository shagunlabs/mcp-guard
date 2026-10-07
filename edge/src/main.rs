//! Sentryra Edge (proxy + embedded PDP). M0 skeleton: loads a mandate and prints a Tier-1 mandate-scope decision.
//! Real transport (rmcp/axum), Cedar and Biscuit land in M2/M4.
use sentryra_mandate::Mandate;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 { eprintln!("usage: sentryra-edge <mandate.json> <tool> <resource>"); std::process::exit(2); }
    let m = match std::fs::read_to_string(&args[1]).map_err(|e| e.to_string()).and_then(|s| Mandate::from_json(&s).map_err(|e| format!("{e:?}"))) {
        Ok(m) => m, Err(e) => { eprintln!("invalid mandate: {e}"); std::process::exit(1); }
    };
    println!("{:?}", m.effect_for(&args[2], &args[3]));
}
