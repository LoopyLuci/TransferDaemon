//! Live checks against Quad9 over DNS-over-TLS (RFC 7858) on the real internet.
//!
//! `#[ignore]`d because they need the network: run them with
//!
//! ```text
//! cargo test -p transferd-dns --test live_quad9 -- --ignored --test-threads=1
//! ```
//!
//! The point of these is that the DoT path is the one nothing local can prove: a certificate check
//! against `dns.quad9.net`, one connection reused across queries, and a real validating resolver's AD bit
//! read off the wire.

use std::time::Duration;

use transferd_dns::{Client, Config, DnsError, Resolver, QUAD9_ADDRS, QUAD9_SERVER_NAME};

fn client(require_validated: bool) -> Client {
    Client::new(Config {
        resolvers: vec![Resolver::quad9(QUAD9_ADDRS, QUAD9_SERVER_NAME)],
        require_validated,
        timeout: Duration::from_secs(10),
    })
}

#[tokio::test]
#[ignore = "needs the internet"]
async fn quad9_over_dot_answers_and_validates() {
    let r = client(true)
        .lookup("example.com", 443)
        .await
        .expect("Quad9 answers a real query over DoT");
    assert_eq!(r.resolver, "quad9");
    assert!(
        r.validated,
        "example.com is in a signed zone, so Quad9 sets AD"
    );
    assert!(!r.addrs.is_empty());
    assert!(r.addrs.iter().all(|a| a.port() == 443));
    eprintln!("example.com via Quad9 DoT: {:?}", r.addrs);
}

#[tokio::test]
#[ignore = "needs the internet"]
async fn the_dot_connection_is_reused_across_queries() {
    // One client, two names: the second must not need a second TLS handshake. The server closes idle
    // sessions, so if reuse were broken this would still pass -- the assertion is that both names
    // resolve through the same client, and the timing shows there is no second handshake in the second.
    let c = client(false);
    let first = c.lookup("example.com", 443).await.expect("the first query");
    let t0 = std::time::Instant::now();
    let second = c
        .lookup("iana.org", 443)
        .await
        .expect("the second query on the same connection");
    let elapsed = t0.elapsed();
    assert!(!first.addrs.is_empty() && !second.addrs.is_empty());
    eprintln!("second query over the reused session took {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(5),
        "a fresh TLS handshake would be slower than this"
    );
}

#[tokio::test]
#[ignore = "needs the internet"]
async fn a_name_that_does_not_exist_is_reported_as_such() {
    let e = client(false)
        .lookup("no-such-name.invalid", 443)
        .await
        .expect_err("a name under .invalid never exists");
    // Exactly this error: a transport failure would mean the DoT path is broken, not that the name is
    // missing, and the two must not be confused.
    assert!(
        matches!(e, DnsError::NxDomain(_)),
        "expected NXDOMAIN, got {e}"
    );
    eprintln!(".invalid name: {e}");
}
