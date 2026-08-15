//! Deterministic stand-in for the `feed_parse` libFuzzer target.
//!
//! Same arrangement as the other crates': it drives `cbna_intel::fuzz::parse_feed`
//! — the exact body the nightly fuzzer runs — over a fixed corpus on stable, so
//! the "feed bytes never panic the parser" contract is checked in ordinary CI.
//!
//! The seeds are one well-formed row of each shipped feed format plus inputs
//! built to break field extraction: short rows, unterminated quotes, a URL with
//! no host, and non-UTF-8 bytes.

use cbna_core::fuzz::Mutator;
use cbna_intel::fuzz::parse_feed;

fn seeds() -> Vec<Vec<u8>> {
    vec![
        // Feodo: plain IP-per-line with a comment.
        b"# Feodo Tracker\n203.0.113.7\n198.51.100.9\n".to_vec(),
        // SSLBL: unquoted JA3 CSV (ja3_md5,Firstseen,Lastseen,Listingreason).
        b"# ja3_md5,Firstseen,Lastseen,Listingreason\n\
          e7d705a3286e19ea42f587b344ee6865,2017-07-14 18:08:15,2019-07-27 20:42:54,Dridex\n"
            .to_vec(),
        // URLhaus: quoted CSV whose URL column carries scheme, port and path.
        b"# id,dateadded,url,url_status,last_online,threat,tags,link,reporter\n\
          \"1\",\"2026-01-01\",\"http://bad.example:8080/x.bin\",\"online\",\"\",\"malware_download\",\"\",\"\",\"r\"\n"
            .to_vec(),
        // Structure-breakers.
        b"\"a\",\"unterminated\n\"1\",\"2\"\n".to_vec(),
        b"\"1\",\"2\",\"http://\"\n".to_vec(),
        b",,,,,,\n#\n   \n".to_vec(),
        vec![0xff, 0xfe, b'\n', b',', b'"', b'\n'],
        Vec::new(),
    ]
}

#[test]
fn feed_parse_never_panics() {
    let seeds = seeds();
    let mut rng = Mutator::new(0x0DDF_00D5_1CE5_CA1E);

    for s in &seeds {
        parse_feed(s);
    }
    for _ in 0..20_000 {
        let seed = &seeds[rng.below(seeds.len())];
        parse_feed(&rng.mutate(seed));
    }
    for _ in 0..5_000 {
        parse_feed(&rng.noise(2048));
    }
}

#[test]
fn seeds_parse_to_the_indicators_they_should() {
    // Guards the corpus: if a seed stops yielding its indicator, the mutation
    // run above quietly degrades into testing the reject path only.
    use cbna_core::ioc::IocSet;
    use cbna_intel::feed::by_id;
    use cbna_intel::parse::parse_into;

    let seeds = seeds();
    let cases = [
        ("feodo", &seeds[0]),
        ("sslbl", &seeds[1]),
        ("urlhaus", &seeds[2]),
    ];
    for (id, bytes) in cases {
        let feed = by_id(id).unwrap();
        let mut set = IocSet::default();
        assert!(
            parse_into(&mut set, feed, bytes) >= 1,
            "seed for {id} should yield at least one indicator"
        );
    }
}
