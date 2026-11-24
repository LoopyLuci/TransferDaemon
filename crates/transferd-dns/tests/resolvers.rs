//! The resolver chain against real DNS servers on real sockets: AD on and off, SERVFAIL, a truncated
//! answer retried over TCP, the order the chain tries, and the fail-closed policy.

mod support;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::Duration;

use support::{Mode, Server, ADDRESS, ADDRESS_V6, NAME};
use transferd_dns::{Client, Config, DnsError, Resolver};

/// A chain of local servers, each in its own mode, with a timeout short enough to keep the tests quick.
fn chain(servers: &[&Server], require_validated: bool) -> Client {
    Client::new(Config {
        resolvers: servers
            .iter()
            .map(|s| Resolver::ironroot(s.addr()))
            .collect(),
        require_validated,
        timeout: Duration::from_millis(1500),
    })
}

#[tokio::test]
async fn a_validated_answer_is_reported_as_validated() {
    let Some(server) = support::start(Mode::Validated).await else {
        eprintln!("no loopback port for the test DNS server");
        return;
    };
    let client = chain(&[&server], false);
    let r = client.lookup(NAME, 443).await.expect("the server answers");
    assert_eq!(r.resolver, "ironroot");
    assert!(
        r.validated,
        "AD was set, so the resolver stood behind the answer"
    );
    assert!(!r.cached);
    // Both types were asked for, so both addresses come back with the port attached.
    assert_eq!(
        r.addrs,
        vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ADDRESS)), 443),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ADDRESS_V6)), 443)
        ]
    );
    assert!(
        server.udp_seen.load(Ordering::Relaxed) >= 2,
        "one query per address type"
    );
    assert_eq!(
        server.tcp_seen.load(Ordering::Relaxed),
        0,
        "nothing was truncated"
    );
}

#[tokio::test]
async fn the_mesh_forwarder_is_asked_like_a_plain_resolver_and_named_as_mesh() {
    let Some(server) = support::start(Mode::Validated).await else {
        eprintln!("no loopback port for the test DNS server");
        return;
    };
    let client = Client::new(Config {
        resolvers: vec![Resolver::Mesh { addr: server.addr() }],
        require_validated: false,
        timeout: Duration::from_millis(1500),
    });
    let r = client.lookup(NAME, 443).await.expect("the forwarder answers");
    assert_eq!(r.resolver, "mesh");
    assert!(r.validated, "AD from the resolver behind it is passed on");
}

#[tokio::test]
async fn an_answer_without_ad_is_not_validated() {
    let Some(server) = support::start(Mode::Unvalidated).await else {
        return;
    };
    let client = chain(&[&server], false);
    let r = client
        .lookup(NAME, 80)
        .await
        .expect("the server still answers");
    assert!(!r.validated, "AD clear means nothing checked this data");
    assert!(
        !r.addrs.is_empty(),
        "the addresses are still usable when validation is not required"
    );
}

#[tokio::test]
async fn requiring_validation_refuses_an_answer_without_ad() {
    let Some(server) = support::start(Mode::Unvalidated).await else {
        return;
    };
    let client = chain(&[&server], true);
    let e = client.lookup(NAME, 80).await.expect_err("fail closed");
    assert!(matches!(e, DnsError::NotValidated { .. }), "got {e:?}");
}

#[tokio::test]
async fn servfail_from_a_validating_resolver_is_bogus_and_does_not_fall_through() {
    let Some(bogus) = support::start(Mode::Servfail).await else {
        return;
    };
    let Some(unreachable) = support::start(Mode::Down).await else {
        return;
    };
    // The system resolver is in the chain and is skipped entirely when validation is required, so a
    // SERVFAIL must not be answered by the operating system either.
    let client = Client::new(Config {
        resolvers: vec![
            Resolver::ironroot(bogus.addr()),
            Resolver::System,
            Resolver::ironroot(unreachable.addr()),
        ],
        require_validated: true,
        timeout: Duration::from_millis(1500),
    });
    let e = client
        .lookup(NAME, 443)
        .await
        .expect_err("bogus is an error");
    assert!(
        matches!(
            e,
            DnsError::Bogus {
                resolver: "ironroot",
                ..
            }
        ),
        "SERVFAIL must read as bogus, not as 'ask someone else': {e:?}"
    );
}

#[tokio::test]
async fn a_truncated_udp_answer_is_retried_over_tcp() {
    let Some(server) = support::start(Mode::TruncateUdp).await else {
        return;
    };
    let client = chain(&[&server], false);
    let r = client
        .lookup(NAME, 53)
        .await
        .expect("the full answer is over TCP");
    assert_eq!(r.addrs.len(), 2);
    assert!(
        server.tcp_seen.load(Ordering::Relaxed) >= 2,
        "the truncated UDP answer must be retried over TCP (RFC 1035 4.1.1)"
    );
}

#[tokio::test]
async fn the_chain_tries_the_resolvers_in_order_and_stops_at_the_first_answer() {
    let Some(first) = support::start(Mode::Down).await else {
        return;
    };
    let Some(second) = support::start(Mode::Validated).await else {
        return;
    };
    let Some(third) = support::start(Mode::Validated).await else {
        return;
    };
    let client = chain(&[&first, &second, &third], false);
    let r = client
        .lookup(NAME, 443)
        .await
        .expect("the second server answers");
    assert_eq!(r.addrs[0].port(), 443);
    assert_eq!(
        third.udp_seen.load(Ordering::Relaxed),
        0,
        "the third is never reached"
    );
    assert!(second.udp_seen.load(Ordering::Relaxed) >= 2);
}

#[tokio::test]
async fn a_resolver_that_never_answers_is_skipped_for_the_next_one() {
    let Some(silent) = support::start(Mode::Silent).await else {
        return;
    };
    let Some(live) = support::start(Mode::Validated).await else {
        return;
    };
    let client = chain(&[&silent, &live], false);
    let r = client
        .lookup(NAME, 443)
        .await
        .expect("a timeout on one resolver is not a failure of the chain");
    assert_eq!(r.addrs.len(), 2);
    assert!(
        silent.udp_seen.load(Ordering::Relaxed) >= 1,
        "it really did try the silent one"
    );
}

#[tokio::test]
async fn nxdomain_is_an_error_and_is_not_retried_elsewhere() {
    let Some(missing) = support::start(Mode::Nxdomain).await else {
        return;
    };
    let Some(other) = support::start(Mode::Validated).await else {
        return;
    };
    let client = chain(&[&missing, &other], false);
    let e = client
        .lookup(NAME, 443)
        .await
        .expect_err("the name does not exist");
    assert!(matches!(e, DnsError::NxDomain(_)), "got {e:?}");
    assert_eq!(
        other.udp_seen.load(Ordering::Relaxed),
        0,
        "another resolver would agree"
    );
}

#[tokio::test]
async fn the_system_resolver_answers_last_and_is_never_validated() {
    // "localhost" is in every system's hosts file, so this needs no network and no DNS server.
    let client = Client::new(Config {
        resolvers: vec![Resolver::System],
        require_validated: false,
        timeout: Duration::from_millis(1500),
    });
    let r = client
        .lookup("localhost", 443)
        .await
        .expect("the OS resolves localhost");
    assert_eq!(r.resolver, "system");
    assert!(
        !r.validated,
        "the operating system's resolver never checks DNSSEC"
    );
    assert!(!r.addrs.is_empty());
}

#[tokio::test]
async fn requiring_validation_leaves_nothing_to_fall_back_to() {
    let client = Client::new(Config {
        resolvers: vec![Resolver::System],
        require_validated: true,
        timeout: Duration::from_millis(500),
    });
    let e = client
        .lookup("localhost", 443)
        .await
        .expect_err("the system resolver cannot validate");
    assert!(matches!(e, DnsError::NoValidatedResolver(_)), "got {e:?}");
}

#[tokio::test]
async fn an_empty_chain_is_an_error_rather_than_a_silent_pass() {
    let client = Client::new(Config {
        resolvers: vec![],
        require_validated: false,
        timeout: Duration::from_millis(500),
    });
    let e = client.lookup(NAME, 443).await.expect_err("nothing to ask");
    assert!(matches!(e, DnsError::NoValidatedResolver(_)), "got {e:?}");
}

#[tokio::test]
async fn an_answer_is_cached_for_its_ttl_and_the_server_is_not_asked_again() {
    let Some(server) = support::start(Mode::Validated).await else {
        return;
    };
    let client = chain(&[&server], false);
    let first = client.lookup(NAME, 443).await.expect("the server answers");
    let after_first = server.udp_seen.load(Ordering::Relaxed);
    let second = client.lookup(NAME, 443).await.expect("from the cache");
    assert!(second.cached, "the second lookup came out of the cache");
    assert!(!first.cached);
    assert_eq!(
        second.addrs, first.addrs,
        "the cache must not change the answer"
    );
    assert_eq!(
        second.resolver, "ironroot",
        "the cache remembers who answered"
    );
    assert_eq!(
        server.udp_seen.load(Ordering::Relaxed),
        after_first,
        "no second query went out"
    );
}

#[tokio::test]
async fn a_cached_unvalidated_answer_is_not_honoured_when_validation_is_required() {
    let Some(server) = support::start(Mode::Unvalidated).await else {
        return;
    };
    // One client that allows it (so the answer lands in the cache) and one that does not: they are
    // separate clients, so the second must ask again and be refused again.
    let relaxed = chain(&[&server], false);
    relaxed.lookup(NAME, 443).await.expect("the server answers");
    let strict = chain(&[&server], true);
    let e = strict.lookup(NAME, 443).await.expect_err("fail closed");
    assert!(matches!(e, DnsError::NotValidated { .. }), "got {e:?}");
}

/// A TTL of 0 is an answer the caller may use once, and the cache must not keep it: a relay address
/// that keeps changing is the case the cache must not paper over.
#[tokio::test]
async fn a_zero_ttl_answer_is_used_but_never_cached() {
    let Some(server) = support::start(Mode::ZeroTtl).await else {
        return;
    };
    let client = chain(&[&server], false);
    let first = client
        .lookup(NAME, 443)
        .await
        .expect("a TTL of 0 is still an answer");
    assert_eq!(first.addrs.len(), 2);
    assert!(!first.cached);
    let after_first = server.udp_seen.load(Ordering::Relaxed);
    let second = client.lookup(NAME, 443).await.expect("asked again");
    assert!(
        !second.cached,
        "TTL 0 means do not cache, so the server is asked again"
    );
    assert!(
        server.udp_seen.load(Ordering::Relaxed) > after_first,
        "and it really was asked again"
    );
}

/// The whole point of the synchronous wrapper: a caller with no runtime of its own still gets an answer.
/// A current-thread runtime is the case `block_in_place` refuses, so that is what is exercised here.
///
/// Not `#[tokio::test]`: a current-thread runtime blocked on `join` cannot run the test server, so this
/// would time out for a reason that has nothing to do with DNS. The server gets its own runtime on its
/// own thread, and the lookup happens on a second one.
#[test]
fn a_lookup_from_a_sync_call_site_works_with_no_runtime_of_its_own() {
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    else {
        eprintln!("no runtime to run the test DNS server on");
        return;
    };
    let server = rt.block_on(support::start(Mode::Validated));
    let Some(server) = server else {
        eprintln!("no loopback port for the test DNS server");
        return;
    };
    let addr = server.addr();
    let out = std::thread::spawn(move || {
        let client = Client::new(Config {
            resolvers: vec![Resolver::ironroot(addr)],
            require_validated: false,
            timeout: Duration::from_millis(2000),
        });
        // A current-thread runtime cannot `block_on` its own future, so this is the awkward caller.
        match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(inner) => inner.block_on(client.resolve(NAME, 8443)),
            Err(e) => Err(DnsError::Config {
                what: e.to_string(),
            }),
        }
    })
    .join();
    match out {
        // Both arms are a failure: assert on the outcome rather than panicking here, so the thread's
        // result and the check are one message.
        Ok(Ok(addrs)) => {
            assert_eq!(addrs.len(), 2, "both the A and the AAAA answer came back");
            assert!(addrs.iter().all(|a| a.port() == 8443));
        }
        other => assert!(other.is_ok(), "the synchronous lookup failed: {other:?}"),
    }
}
