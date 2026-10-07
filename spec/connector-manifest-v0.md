# Connector manifest v0 (draft)
`{spec:"sentryra.connector/v0", connector, version, tools:[{name, resource_template, consequential, output_trust, sink_args[]}]}`
- `output_trust` defaults to `untrusted`: outputs are fingerprinted for taint (M5).
- `sink_args` are arguments checked for taint (recipients, URLs, branch names…).
- `consequential` tools fail closed. Tool descriptions from upstream servers are never trusted; the manifest is pinned by hash.
Example: `examples/connector-github.json`.

- `args` (optional): map of argument name → kind (`email`, `url`, `host`, `path`, `branch`, `amount`, `cmd`, `sql`, `user`, `group`, `region`, `text`, `other`). Constraints apply by kind. Without a mapping, kinds are inferred from conventional names.
- Taint is only checked on declared `sink_args`.
