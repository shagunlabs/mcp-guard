# Sentryra Mandate v0 (draft, Apache-2.0)
A mandate is a signed, scoped, expiring delegation from a principal to an agent; re-delegation only narrows it.
Example: `examples/mandate-v0.json`.
## Required fields
`mandate_id`, `spec` (= `sentryra.mandate/v0`), `tenant`, `principal`, `agent` (incl. `cnf` key binding), `purpose` (captured from the principal at consent, never from agent context), `scopes[]`, `default_effect` (MUST be `deny`), `not_before`, `expires_at`.
## Scopes
Each scope: `tool`, `resource`, `effect` ∈ {allow, escalate, deny}, `approvers` (REQUIRED when `escalate`), optional `constraints`. When several scopes match, strictest wins (deny > escalate > allow). No match → `default_effect`.
## Wire format
Compiled to a Biscuit v3.3 token signed by the tenant root key (M1). Attenuation appends blocks that can only narrow.
## Open items
Wildcard/resource-pattern grammar; constraint vocabulary; canonical time-zone handling for `context_constraints.hours`.
