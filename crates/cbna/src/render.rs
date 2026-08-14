//! Terminal rendering for the report.
//!
//! No table crate: the shapes here are fixed and a hand-rolled column writer
//! keeps the binary dependency-light and the output easy to pipe.

use cbna_core::analysis::{Report, Severity};
use cbna_core::time::{human_bytes, human_duration, human_percent};
use std::io::Write;

/// ANSI styling, suppressed when output is redirected or `NO_COLOR` is set.
pub struct Style {
    enabled: bool,
}

impl Style {
    pub fn detect(force_plain: bool) -> Self {
        let enabled = !force_plain
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true);
        Self { enabled }
    }

    fn wrap(&self, code: &str, s: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    pub fn cyan(&self, s: &str) -> String {
        self.wrap("36", s)
    }
    pub fn severity(&self, sev: Severity, s: &str) -> String {
        match sev {
            Severity::High => self.wrap("1;31", s),
            Severity::Medium => self.wrap("1;33", s),
            Severity::Low => self.wrap("36", s),
            Severity::Info => self.wrap("2", s),
        }
    }
}

/// Column alignment.
#[derive(Clone, Copy, PartialEq)]
pub enum Align {
    Left,
    Right,
}

pub struct Table {
    headers: Vec<String>,
    aligns: Vec<Align>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(headers: &[&str], aligns: &[Align]) -> Self {
        Self {
            headers: headers.iter().map(|s| s.to_string()).collect(),
            aligns: aligns.to_vec(),
            rows: Vec::new(),
        }
    }

    pub fn row(&mut self, cells: Vec<String>) {
        self.rows.push(cells);
    }

    pub fn write(&self, out: &mut impl Write, style: &Style, indent: &str) -> std::io::Result<()> {
        if self.rows.is_empty() {
            writeln!(out, "{indent}{}", style.dim("(none)"))?;
            return Ok(());
        }
        let cols = self.headers.len();
        let mut widths: Vec<usize> = self.headers.iter().map(|h| display_width(h)).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate().take(cols) {
                widths[i] = widths[i].max(display_width(cell));
            }
        }

        let header: Vec<String> = self
            .headers
            .iter()
            .enumerate()
            .map(|(i, h)| pad(h, widths[i], self.aligns[i]))
            .collect();
        writeln!(out, "{indent}{}", style.dim(&header.join("  ")))?;

        for row in &self.rows {
            let line: Vec<String> = (0..cols)
                .map(|i| {
                    let cell = row.get(i).map(String::as_str).unwrap_or("");
                    pad(cell, widths[i], self.aligns[i])
                })
                .collect();
            writeln!(out, "{indent}{}", line.join("  ").trim_end())?;
        }
        Ok(())
    }
}

fn display_width(s: &str) -> usize {
    s.chars().count()
}

fn pad(s: &str, width: usize, align: Align) -> String {
    let len = display_width(s);
    if len >= width {
        return s.to_string();
    }
    let fill = " ".repeat(width - len);
    match align {
        Align::Left => format!("{s}{fill}"),
        Align::Right => format!("{fill}{s}"),
    }
}

fn heading(out: &mut impl Write, style: &Style, text: &str) -> std::io::Result<()> {
    writeln!(out)?;
    writeln!(out, "{}", style.bold(&text.to_uppercase()))?;
    Ok(())
}

/// Print the whole report in reading order: what was seen, what stood out,
/// then the supporting tables.
pub fn report(out: &mut impl Write, r: &Report, style: &Style, top: usize) -> std::io::Result<()> {
    let s = &r.summary;

    writeln!(out, "{}", style.bold("Custom Built Network Analyzer"))?;
    writeln!(out, "{}", style.dim(&format!("source: {}", r.source)))?;

    heading(out, style, "summary")?;
    writeln!(
        out,
        "  {:<16}{}  ({:.1} pkt/s)",
        "Packets", s.packets, s.packets_per_sec
    )?;
    writeln!(
        out,
        "  {:<16}{}  ({:.2} Mbit/s)",
        "Volume",
        human_bytes(s.bytes),
        s.bits_per_sec / 1e6
    )?;
    writeln!(out, "  {:<16}{}", "Flows", s.flows)?;
    writeln!(out, "  {:<16}{}", "Hosts", s.hosts)?;
    writeln!(
        out,
        "  {:<16}{}",
        "Duration",
        human_duration(s.duration_secs)
    )?;
    if let (Some(first), Some(last)) = (&s.first_seen, &s.last_seen) {
        writeln!(out, "  {:<16}{first} → {last}", "Window")?;
    }
    writeln!(
        out,
        "  {:<16}ipv4 {} · ipv6 {} · arp {} · tcp {} · udp {} · icmp {}",
        "Breakdown",
        s.counts.ipv4,
        s.counts.ipv6,
        s.counts.arp,
        s.counts.tcp,
        s.counts.udp,
        s.counts.icmp
    )?;
    if s.truncated_packets > 0 || s.decode_warnings > 0 || s.counts.fragments > 0 {
        writeln!(
            out,
            "  {:<16}{} truncated · {} decode warnings · {} fragments",
            "Caveats", s.truncated_packets, s.decode_warnings, s.counts.fragments
        )?;
    }

    heading(out, style, "findings")?;
    if r.findings.is_empty() {
        writeln!(out, "  {}", style.dim("No heuristics fired."))?;
    } else {
        for f in &r.findings {
            let tail = if f.technique.is_empty() {
                f.id.clone()
            } else {
                format!("{} · ATT&CK {}", f.id, f.technique.join(", "))
            };
            writeln!(
                out,
                "  {} {}  {}",
                style.severity(f.severity, &format!("[{}]", f.severity)),
                style.bold(&f.title),
                style.dim(&tail)
            )?;
            for line in wrap_text(&f.detail, 92) {
                writeln!(out, "      {}", style.dim(&line))?;
            }
            for e in &f.evidence {
                writeln!(out, "      · {e}")?;
            }
            writeln!(out)?;
        }
    }

    heading(out, style, "top talkers")?;
    let mut t = Table::new(
        &["HOST", "SENT", "RECEIVED", "TOTAL", "PEERS", "SCOPE"],
        &[
            Align::Left,
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Left,
        ],
    );
    for h in r.talkers.iter().take(top) {
        t.row(vec![
            h.address.clone(),
            human_bytes(h.bytes_sent),
            human_bytes(h.bytes_received),
            human_bytes(h.total_bytes),
            h.peers.to_string(),
            if h.private { "private" } else { "public" }.to_string(),
        ]);
    }
    t.write(out, style, "  ")?;

    heading(out, style, "services")?;
    let mut t = Table::new(
        &["SERVICE", "PROTO", "PORT", "FLOWS", "PACKETS", "BYTES"],
        &[
            Align::Left,
            Align::Left,
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Right,
        ],
    );
    for s in r.services.iter().take(top) {
        t.row(vec![
            s.service.clone(),
            s.protocol.clone(),
            s.port.to_string(),
            s.flows.to_string(),
            s.packets.to_string(),
            human_bytes(s.bytes),
        ]);
    }
    t.write(out, style, "  ")?;

    heading(out, style, "top flows")?;
    let mut t = Table::new(
        &["FLOW", "SCOPE", "APP", "PACKETS", "BYTES", "DURATION"],
        &[
            Align::Left,
            Align::Left,
            Align::Left,
            Align::Right,
            Align::Right,
            Align::Right,
        ],
    );
    for f in r.top_flows.iter().take(top) {
        let app = if f.protocols.is_empty() {
            f.service.clone().unwrap_or_default()
        } else {
            f.protocols.join(",")
        };
        let app = match (&f.sni, &f.resolved_dest) {
            // SNI is the strongest name; fall back to the DNS-resolved host so a
            // plain IP flow still reads as a name when one was observed.
            (Some(sni), _) => format!("{app} {sni}"),
            (None, Some(name)) => format!("{app} {name}").trim().to_string(),
            (None, None) => app,
        };
        t.row(vec![
            f.flow.clone(),
            f.scope.clone(),
            app,
            f.packets.to_string(),
            human_bytes(f.bytes),
            human_duration(f.duration_secs),
        ]);
    }
    t.write(out, style, "  ")?;

    if !r.beacons.is_empty() {
        heading(out, style, "beacon candidates")?;
        let mut t = Table::new(
            &["FLOW", "INTERVAL", "JITTER", "SAMPLES", "CONFIDENCE", "SNI"],
            &[
                Align::Left,
                Align::Right,
                Align::Right,
                Align::Right,
                Align::Right,
                Align::Left,
            ],
        );
        for b in r.beacons.iter().take(top) {
            t.row(vec![
                b.flow.clone(),
                human_duration(b.interval),
                human_percent(b.jitter),
                b.samples.to_string(),
                format!("{:.2}", b.confidence),
                b.sni.clone().unwrap_or_default(),
            ]);
        }
        t.write(out, style, "  ")?;
    }

    if r.dns.unique_names > 0 {
        heading(out, style, "dns")?;
        writeln!(
            out,
            "  {}",
            style.dim(&format!(
                "{} unique names · {} queries · {} NXDOMAIN",
                r.dns.unique_names, r.dns.queries, r.dns.nxdomain
            ))
        )?;
        let mut t = Table::new(&["NAME", "LOOKUPS"], &[Align::Left, Align::Right]);
        for (name, count) in r.dns.top_names.iter().take(top) {
            t.row(vec![name.clone(), count.to_string()]);
        }
        t.write(out, style, "  ")?;
    }

    if r.tls.handshakes > 0 {
        heading(out, style, "tls")?;
        writeln!(
            out,
            "  {}",
            style.dim(&format!(
                "{} handshakes · {} unique SNI · {} without SNI · {} obsolete versions",
                r.tls.handshakes, r.tls.unique_sni, r.tls.no_sni, r.tls.obsolete_versions
            ))
        )?;
        let mut t = Table::new(&["SNI", "COUNT"], &[Align::Left, Align::Right]);
        for (sni, count) in r.tls.top_sni.iter().take(top) {
            t.row(vec![sni.clone(), count.to_string()]);
        }
        t.write(out, style, "  ")?;

        if !r.tls.top_ja3.is_empty() {
            let mut t = Table::new(
                &["JA3", "COUNT", "EXAMPLE SNI"],
                &[Align::Left, Align::Right, Align::Left],
            );
            for (hash, count, sni) in r.tls.top_ja3.iter().take(top) {
                t.row(vec![
                    hash.clone(),
                    count.to_string(),
                    sni.clone().unwrap_or_default(),
                ]);
            }
            t.write(out, style, "  ")?;
        }
    }

    if r.http.requests > 0 || r.http.responses > 0 {
        heading(out, style, "http")?;
        writeln!(
            out,
            "  {}",
            style.dim(&format!(
                "{} requests · {} responses · {} with cleartext Authorization",
                r.http.requests, r.http.responses, r.http.cleartext_auth
            ))
        )?;
        let mut t = Table::new(&["HOST", "REQUESTS"], &[Align::Left, Align::Right]);
        for (host, count) in r.http.top_hosts.iter().take(top) {
            t.row(vec![host.clone(), count.to_string()]);
        }
        t.write(out, style, "  ")?;
    }

    writeln!(out)?;
    writeln!(
        out,
        "{}",
        style.cyan(&format!("{} · {}", r.tool, r.generated_at))
    )?;
    Ok(())
}

/// Soft-wrap prose to a width, breaking on whitespace.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_aligns_columns() {
        let mut t = Table::new(&["A", "B"], &[Align::Left, Align::Right]);
        t.row(vec!["short".into(), "1".into()]);
        t.row(vec!["much longer".into(), "1000".into()]);
        let mut out = Vec::new();
        t.write(&mut out, &Style { enabled: false }, "").unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // The widest cell fixes the column, and right-aligned numbers line up
        // on their last character.
        assert_eq!(lines[2], "much longer  1000");
        assert!(lines[1].starts_with("short "));
        assert!(lines[1].ends_with("   1"));
        assert_eq!(lines[1].len(), lines[2].len());
        assert!(lines[0].starts_with("A "));
        assert!(lines[0].trim_end().ends_with('B'));
    }

    #[test]
    fn empty_table_renders_placeholder() {
        let t = Table::new(&["A"], &[Align::Left]);
        let mut out = Vec::new();
        t.write(&mut out, &Style { enabled: false }, "  ").unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "  (none)\n");
    }

    #[test]
    fn style_can_be_disabled() {
        let plain = Style::detect(true);
        assert_eq!(plain.bold("x"), "x");
        let styled = Style { enabled: true };
        assert_eq!(styled.bold("x"), "\x1b[1mx\x1b[0m");
    }

    #[test]
    fn wraps_prose_on_word_boundaries() {
        let lines = wrap_text("the quick brown fox jumps over the lazy dog", 15);
        assert!(lines.iter().all(|l| l.chars().count() <= 15));
        assert_eq!(lines[0], "the quick brown");
        assert_eq!(lines.concat().replace(' ', "").len(), 35);
    }
}
