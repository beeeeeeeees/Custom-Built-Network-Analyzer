# Working in this repo

Rust workspace, four crates. Read `README.md` first for what the tool does.

## Build and check

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets   # must stay clean
cargo fmt --all
cargo clippy -p cbna --features live --all-targets
```

Live-capture code (`crates/cbna-capture/src/live.rs`, `crates/cbna/src/livecmd.rs`)
is behind `--features live` and is NOT compiled by a plain `cargo check`. Always
lint the live build separately after touching it.

The `live` feature needs `vendor/npcap-sdk` on Windows; run
`./scripts/fetch-npcap-sdk.ps1` if it is missing. `.cargo/config.toml` points the
`pcap` build script at it.

## Architecture invariants

- **`cbna-core` does no I/O and is not async.** Keep it that way; it is the only
  crate the analysis correctness depends on, and it stays trivially testable.
- **Decoding never panics and never hard-fails a packet.** Parse errors become
  entries in `DecodedPacket::warnings`; lower layers are still reported. There
  is a fuzz-ish test (`packet::tests::arbitrary_bytes_never_panic`) guarding
  this — do not weaken it.
- **Every length read from the wire is bounds-checked before allocating**, and
  every loop over attacker-controlled structure (VLAN stacks, IPv6 extension
  headers, DNS compression pointers, TLS extensions, pcapng blocks) is bounded.
  New parsers must follow the same pattern; use `bytes::Reader`, not raw slicing.
- **Client/server is resolved by `Flow::client_direction()`, not key order.**
  The canonical flow key sorts endpoints by address so both directions share a
  record; it carries no directional meaning. Anything that means "the side that
  initiated" must go through `client()` / `server()` / `client_stats()` /
  `server_stats()`.
- **Unbounded growth is a bug.** Per-flow sample vectors, DNS name sets, HTTP
  header values and evidence lists are all capped. Add a cap to anything new
  that grows per packet.

## Adding a detection

Add a function in `crates/cbna-core/src/analysis/findings.rs` and call it from
`collect()`. Every finding must:

- have a stable kebab-case `id` (downstream tooling matches on it),
- carry concrete `evidence` naming the flows or hosts involved,
- state in `detail` what benign activity produces the same pattern.

Thresholds belong in `AnalysisConfig`, and should get a CLI flag in
`TuningArgs` if an analyst would plausibly want to change them per network.

## Dashboard

`crates/cbna-web/assets/index.html` is a single self-contained file, no build
step and no external requests. It polls `/api/report` every 2s and redraws only
when the generation counter changes. Nothing here is covered by `cargo test`, so
the invariants below are enforced by reading only — be deliberate.

Report content is attacker-influenced — hostnames, user agents, URIs. The
dashboard inserts all of it via `textContent`; there is no `innerHTML` anywhere
in that file and it must stay that way. `h()` is the only element constructor
and it takes text, never markup.

### The filter model

Filter chips are the spine of the page. `buildCtx()` compiles every active chip
into one context per render and each panel narrows itself against it, so a
finding's evidence, the flow table and the DNS panel always agree about what is
in scope.

- **Flows are the join table.** Panels whose rows carry no host or service field
  are narrowed through the flows that survive the same filters
  (`ctx.derived*`). Do not invent a different linkage for a new panel.
- **A panel that cannot evaluate a filter must say so.** Every `panelMeta()`
  call passes the list of filter kinds that panel actually `handled`; the header
  then renders "⚠ not narrowed" for the rest. Silently ignoring a chip makes the
  page assert a relationship the API never provided.
- **Panel headers always show `shown of total`.** A filtered-to-empty panel and
  a genuinely empty one look identical otherwise, and that misreads as "this
  host did nothing else."
- `window` is deliberately singular — a second time window is always an empty
  intersection. Keep that in `addFilter()`.

### The table engine

`makeTable()` does keyed reconciliation: matched rows keep their DOM element and
have only changed cells patched. That is what stops a 2s poll from destroying
scroll position, text selection and the drawer. It depends entirely on row keys
being **stable across polls** — key a new table on flow key or address, never on
array index or anything derived from sort order.

`interacting()` is the second guard: payloads are held, not applied, while the
user is typing, dragging or mid-selection. If a new control can be interacted
with over multiple frames, it belongs in that check.

### State that outlives the process

Filters, search text, sort, collapse state, the selected flow, the timeline
metric and theme all persist in `localStorage`.
`loadState()` re-validates every field on the way in — kind and value are
type-checked, filters are capped at 24, sort directions must be ±1. That store
is user-writable; treat it as untrusted input, not as your own output.

### Two couplings that break silently

`percent()` deliberately mirrors `cbna_core::time::human_percent`. Beacon jitter
spans orders of magnitude and a fixed decimal count renders a 0.004% metronome
and a 0.4% merely-regular flow identically. If you change the thresholds in one,
change them in the other — both have tests pinned to the same inputs.

Severity badge classes are derived from the severity string in the JSON, which
is why `Severity` serializes lowercase to match its `Display` impl. Rename
either spelling and badges lose their colour while the severity filter quietly
matches nothing; `severity_serializes_lowercase_to_match_display` pins it.

## Sample data

`cargo run -p cbna --example make-sample -- samples/demo.pcap` writes a
synthetic capture that trips every detector. Use it to eyeball changes to
reports or the dashboard. `samples/` is gitignored.
