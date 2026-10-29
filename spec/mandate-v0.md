# Sentryra Mandate v0 (draft, Apache-2.0)
A mandate is a signed, scoped, expiring delegation from a principal to an agent; re-delegation only narrows it.
Example: `examples/mandate-v0.json`.
## Required fields
`mandate_id`, `spec` (= `sentryra.mandate/v0`), `tenant`, `principal`, `agent` (incl. `cnf` key binding), `purpose` (captured from the principal at consent, never from agent context), `scopes[]`, `default_effect` (MUST be `deny`), `not_before`, `expires_at`.
## Scopes
Each scope: `tool`, `resource`, `effect` ∈ {allow, escalate, deny}, `approvers` (REQUIRED when `escalate`), optional `constraints`. The issuer signs `approvers` into the token (`scope_approvers` fact); tokens without it still verify and then carry no list. On approve, a hold from an escalate scope requires the self-declared approver name to match one listed entry exactly (a consistency check, not authentication). When several scopes match, strictest wins (deny > escalate > allow). No match → `default_effect`.
## Constraint vocabulary (v0)
Scope `constraints` use these dotted keys (adopted from the ML team's bench v0.2 schema). Tier 1 evaluates them deterministically against call arguments, using the connector manifest's argument kinds (`args`) or the listed default argument names. A scope grants only if **all** its constraints pass. A failed constraint denies. **Unknown keys escalate** (fail closed, never ignored). Values starting with `$` are context bindings (e.g. `$ticket.requester`). The v0 Edge can't resolve them yet, so a call that touches the bound argument escalates.

| Key | Value | Applies to | Rule |
|---|---|---|---|
| `sql.statement_types` | list | `sql` args | every statement class (SELECT, INSERT, UPDATE, DELETE, MERGE; DDL by verb, e.g. DROP) must be listed; nested DML in CTEs and stacked statements count. Listing a DDL verb lifts the global DDL forbid, but the call still escalates |
| `sql.tables` | list | `sql` args | every table after FROM/JOIN/INTO/UPDATE/TABLE must be listed |
| `max_rows` | int | result | row-cap obligation on the tool output (recorded; proxy enforcement pending) |
| `untainted_args` | list of arg names | named args | deny if the value was copied from untrusted tool output |
| `fs.path_prefix` | string or list | `path` args | lexically normalised path must be under a prefix; `..` traversal always denied |
| `repo.branches` | list of globs | `branch` args (`branch`, `base`, `head`, `ref`) | glob match (`*` within a segment, `**` across) |
| `repo.numbers` | list | `number`, `pr`, `issue` | exact allowlist |
| `repo.permissions` | list | `permission`, `role` | exact allowlist |
| `mail.recipient_domains` | list | every `email` arg (`to`, `cc`, `bcc`, `email`, `from`, …), plus every non-`email`, non-`text` arg for address-shaped values | domain equals or is a subdomain; non-ASCII (homoglyph) domains denied. Same fail-closed rules as `mail.recipients`: no `email` arg with a value, or catalogue `external_send` tool declaring no `email` arg => escalate; an out-of-domain address in any other arg => deny; an in-domain address in a non-recipient field => escalate; `text` args ignored |
| `mail.recipients` | list | every `email` arg (incl. `from`), plus every non-`email`, non-`text` arg for address-shaped values | exact address (case-insensitive, trimmed). Fail closed: no `email` arg with a value in the call, or catalogue `external_send` tool declaring no `email` arg => escalate; an address not in the list in any other arg (e.g. `forward_to`, nested, `mailto:`) => deny; a listed address in a non-recipient field => escalate. Free-text `text` args (`body`) are content and ignored |
| `mail.query` | list | `q`, `query` | exact allowlist |
| `shell.cmd_prefix` | list | `cmd` args | command equals a prefix or starts with `prefix `; shell metacharacters ``; \| & ` $ < > ( ) { } \`` and newlines denied |
| `amount.max` | number | `amount` args | 0 ≤ value ≤ max; numeric strings accepted |
| `amount.currency` | string or list | `currency` | exact (case-insensitive) |
| `chat.channels` | list | `channel` | exact allowlist |
| `idp.users` / `idp.groups` | list | `user`, `username` / `group` | exact allowlist |
| `db.tenants` | list | `tenant` | exact allowlist |
| `deploy.regions` / `deploy.builds` | list | `region(s)` / `build`, `version` | exact allowlist; arrays: every element; `*` is not a wildcard |

Implementation: `crates/pdp/src/constraints.rs` (`VOCABULARY`).

## Wire format
Compiled to a Biscuit v3.3 token signed by the tenant root key (M1). Attenuation appends blocks that can only narrow.
## Open items
Wildcard/resource-pattern grammar; resolving `$` context bindings; `max_rows` enforcement on results; canonical time-zone handling for `context_constraints.hours`.
