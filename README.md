# Custom Built Network Analyzer (`cbna`)

A network traffic analyzer written from the packet bytes up in Rust. It reads
pcap/pcapng files or captures live off an interface, decodes L2 through L7 with
hand-written parsers, tracks bidirectional flows, and applies detection
heuristics aimed at incident response — beaconing, DNS tunnelling, port
scanning, upload-heavy egress, cleartext credentials, ARP conflicts.

Output goes three ways: a terminal report, a JSON document, and a live web
dashboard.

```
cbna analyze capture.pcap          # terminal report
cbna analyze capture.pcap --json - # machine-readable
cbna serve capture.pcap            # dashboard at http://127.0.0.1:8787
cbna serve --iface eth0            # live dashboard
cbna capture --iface eth0 -w out.pcap
```

## Why the parsers are hand-written

The decoders (`cbna-core`) and the capture-file readers (`cbna-capture`) do not
use a packet-parsing crate. File and frame parsing is the code most exposed to
untrusted input, so the bounds checks live in-tree where they can be audited and
fuzzed. Every length read off the wire is validated before it drives an
allocation, every loop that follows an attacker-controlled pointer or header
chain is bounded, and decode failures degrade to a per-packet warning rather
than aborting the run.

## Layout

| Crate | Responsibility |
| --- | --- |
| `cbna-core` | Decoding, flow tracking, analysis. No I/O, no async. |
| `cbna-capture` | Packet sources: pcap/pcapng readers, pcap writer, live interface. |
| `cbna-web` | Axum dashboard serving analysis snapshots. |
| `cbna` | CLI binary tying the three together. |

Both front-ends drive the same path — `Source` → `decode()` → `Analyzer` — so a
live capture and a saved file produce identical findings.

## What it decodes

- **L2** — Ethernet II, stacked 802.1Q/802.1ad VLANs, ARP
- **L3** — IPv4 (fragmentation flags, options), IPv6 (extension-header chain
  walking), ICMP and ICMPv6
- **L4** — TCP (flags, MSS, window scale, SACK, timestamps), UDP
- **L7** — DNS (with name decompression), HTTP/1.x headers, TLS ClientHello and
  ServerHello with SNI, ALPN, and **JA3 / JA3S** fingerprints
- **Link types** — Ethernet, raw IP, BSD/OpenBSD loopback, Linux cooked v1 and v2
- **Files** — pcap (both byte orders, µs and ns timestamps) and pcapng
  (multi-section, `if_tsresol`-aware, EPB and SPB blocks)

## Detections

Each finding names the flows or hosts behind it, and each says out loud what
benign thing produces the same pattern — these are leads, not verdicts.

| ID | Severity | Signal |
| --- | --- | --- |
| `periodic-beaconing` | high/medium | Median inter-arrival regularity per flow, scored with MAD so packet loss and sleep-skew do not wreck it |
| `dns-subdomain-volume` | high | Many distinct subdomains under one parent — the DNS-tunnelling shape |
| `high-entropy-dns` | high/medium | Shannon entropy of the leftmost label, weighted up when NXDOMAIN accompanies it |
| `port-scan` | high | SYNs to many ports on one destination, cross-checked against unanswered flows |
| `arp-address-conflict` | high | One IP claimed by multiple MACs |
| `cleartext-http-credentials` | high | `Authorization` observed over plain HTTP (the value is never stored) |
| `outbound-upload-heavy` | medium | Internal host pushing far more out than it pulls back |
| `obsolete-tls` | medium | SSL 3.0 / TLS 1.0 / TLS 1.1 negotiated |
| `cleartext-service` | low | Unencrypted protocols carrying real traffic |
| `capture-quality` | info | Snaplen truncation, fragments, decode warnings — caveats on everything above |

Thresholds are tunable per run: `--beacon-jitter`, `--beacon-min-packets`,
`--dns-subdomains`, `--scan-ports`.

### On flow direction

The flow table keys on a canonicalised 5-tuple so both directions share a
record, which says nothing about who called whom. Client and server are resolved
separately: a bare SYN is authoritative, and failing that — live captures very
often start mid-conversation — the well-known or lower port is taken as the
service. Getting this wrong would label every outbound connection to a
low-numbered address as inbound, and invert every upload ratio.

## Build

Requires Rust 1.82 or newer.

```powershell
cargo build --release
cargo test --workspace
```

The release binary lands at `target/release/cbna.exe`.

### Live capture

Live capture is behind the `live` feature so the default build has no external
dependencies.

1. Install the **Npcap runtime** from <https://npcap.com> (Windows) or have
   `libpcap` present (Linux/macOS).
2. On Windows, fetch the build-time SDK once:
   ```powershell
   ./scripts/fetch-npcap-sdk.ps1
   ```
   It lands in `vendor/npcap-sdk`, which `.cargo/config.toml` already points the
   build at. The directory is gitignored.
3. Build:
   ```powershell
   cargo build --release --features live
   ```

Capturing needs elevated privileges: Administrator on Windows, root or
`CAP_NET_RAW` on Linux.

```powershell
cbna devices                                  # list interfaces
cbna capture --iface "\Device\NPF_{...}" --duration 30 -w out.pcap
cbna serve --iface "\Device\NPF_{...}" --filter "not port 22"
cbna serve --iface "\Device\NPF_{...}" -w session.pcap   # watch live and keep the packets
```

`serve -w` flushes on every dashboard refresh rather than only at shutdown, so
a session ended by killing the process still leaves a complete, readable file.

## Try it without a capture

A generator writes a synthetic pcap that trips all ten detectors — including a
TLS 1.0 appliance, a fragmented datagram, and frames clipped by a short snaplen,
so the capture-quality caveats appear too:

```powershell
cargo run -p cbna --example make-sample -- samples/demo.pcap
cargo run -p cbna -- analyze samples/demo.pcap
```

## CLI

```
cbna analyze <FILE>            Analyse a capture file
  --json <PATH|->              Write the full report as JSON
  --top <N>                    Rows per table (default 20)
  --limit <N>                  Stop after N packets
  --packets                    One line per packet as it decodes
  --findings-only              Print only the findings section

cbna serve [FILE]              Web dashboard
  --iface <NAME>               Live capture instead of a file
  --filter <EXPR>              BPF filter for live capture
  -w, --write <PATH>           Also save live packets to a pcap
  --bind <ADDR>                Default 127.0.0.1:8787
  --refresh <SECS>             Snapshot interval when live (default 2)

cbna capture                   Live capture to terminal and/or disk
  --iface <NAME>  --filter <EXPR>  --count <N>  --duration <SECS>
  -w, --write <PATH>           Save as pcap
  --snaplen <N>  --no-promisc  --packets

cbna devices                   List capture interfaces

Global: --plain (no colour), --log <LEVEL>
```

### Dashboard API

The dashboard is same-origin, but the JSON is CORS-open so you can pull it into
a notebook while it runs.

| Endpoint | Returns |
| --- | --- |
| `GET /api/report` | Full report plus capture status and a generation counter |
| `GET /api/status` | Live capture counters only |
| `GET /api/findings` | Findings array |
| `GET /api/flows?q=&limit=` | Flows, filtered by substring |
| `GET /api/health` | Liveness and whether a snapshot exists |

`503` means no snapshot has been published yet, which is normal in the first
seconds of a live run.

## Operational notes

- **The dashboard binds to loopback by default.** It renders decoded traffic
  including hostnames and URIs; do not bind it to `0.0.0.0` on a shared host.
  Everything from the wire is inserted as text nodes, never parsed as HTML.
- **Credential values are never stored.** Cleartext `Authorization` is recorded
  as a boolean plus the request line.
- **No stream reassembly.** HTTP is decoded when headers begin a segment, which
  covers the first request/response of virtually every connection. IP fragments
  are counted and flagged, not reassembled.
- **Memory is bounded.** Per-flow timestamp samples, DNS name sets, and header
  values are all capped, so a hostile or very long capture cannot grow the
  process without limit. Truncation is reported in the findings.

## Testing

95 tests, run with `cargo test --workspace`. They cover the decoders against
truncated, malformed, and hostile input (cyclic DNS compression pointers,
implausible packet lengths, arbitrary byte fuzz across every link type), the
beacon scorer against metronomes, jittered beacons, dropped check-ins and bursty
noise, capture-file round trips in both byte orders and both timestamp
resolutions, and flow direction resolution.

## License

MIT
