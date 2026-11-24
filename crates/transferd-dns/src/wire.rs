//! DNS wire format: encoding a query and decoding an answer, written here rather than pulled in as a
//! dependency (it is a few hundred lines, and a relay's address should come from code we can read).
//!
//! Only what a validating client needs: a query with EDNS0 and the DO bit set, A and AAAA answers, a CNAME
//! chain inside the answer section, the rcode and the AD bit. Names are compressed (RFC 1035 §4.1.4) on the
//! way in, and never compressed on the way out.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// QR: this message is a response.
pub const FLAG_RESPONSE: u16 = 1 << 15;
/// RD: recursion desired.
pub const FLAG_RD: u16 = 1 << 8;
/// AD: the data has been checked by the resolver and is authentic (RFC 4035 §3.2.3).
pub const FLAG_AD: u16 = 1 << 5;
/// TC: this message was truncated; ask again over TCP (RFC 1035 §4.1.1).
pub const FLAG_TC: u16 = 1 << 9;

/// IN: the Internet class.
pub const CLASS_IN: u16 = 1;
/// A: an IPv4 address.
pub const TYPE_A: u16 = 1;
/// CNAME: the canonical name for this alias.
pub const TYPE_CNAME: u16 = 5;
/// AAAA: an IPv6 address.
pub const TYPE_AAAA: u16 = 28;
/// OPT: the EDNS0 pseudo-record (RFC 6891).
pub const TYPE_OPT: u16 = 41;

/// NOERROR.
pub const RCODE_NOERROR: u8 = 0;
/// SERVFAIL: the resolver could not answer. From a validating resolver this means "bogus" — a name whose
/// signatures do not check out (RFC 4035 §3.2.3) — so it must not be retried somewhere unvalidated.
pub const RCODE_SERVFAIL: u8 = 2;
/// NXDOMAIN: the name does not exist.
pub const RCODE_NXDOMAIN: u8 = 3;

/// The largest UDP response we ask a resolver to send (our advertised buffer, RFC 6891 §6.2.3).
pub const EDNS_UDP_PAYLOAD: u16 = 1232;

/// A name that cannot be put on the wire: an empty label, a label over 63 bytes, a name over 255.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadName(pub String);

impl std::fmt::Display for BadName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is not a usable DNS name", self.0)
    }
}

impl std::error::Error for BadName {}

/// A response that is not shaped like a DNS message we can use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The message ended in the middle of a field.
    Truncated,
    /// A compression pointer sent us backwards forever (RFC 1035 §4.1.4 pointers must go earlier).
    CompressionLoop,
    /// Not a response at all.
    NotAResponse,
    /// The ID is not the one we asked for — a different transaction, or a forged reply.
    IdMismatch { got: u16, want: u16 },
    /// The question in the answer is not the question we asked.
    QuestionMismatch {
        got: String,
        got_type: u16,
        want: String,
        want_type: u16,
    },
    /// The header's record counts do not match the records actually present.
    ShortRecord,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "DNS message ends early"),
            Self::CompressionLoop => write!(f, "compression pointer loop"),
            Self::NotAResponse => write!(f, "not a DNS response"),
            Self::IdMismatch { got, want } => {
                write!(f, "response id {got} is not the query id {want}")
            }
            Self::QuestionMismatch {
                got,
                got_type,
                want,
                want_type,
            } => {
                write!(
                    f,
                    "response question {got}/{got_type} is not the query {want}/{want_type}"
                )
            }
            Self::ShortRecord => write!(f, "DNS record is shorter than its own fields say"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encode a standard recursive query with EDNS0 and the DO bit set, so a validating resolver sends back
/// RRSIGs and sets AD when the answer checks out (RFC 4035 §3.2.1, §3.2.3).
///
/// `id` is the transaction id; the caller picks it and the caller checks it comes back.
pub fn encode_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, BadName> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    // QR clear, opcode QUERY, RD set. AD is a response flag: RFC 4035 §3.1.6 has a server clear it in a
    // query, so we leave it clear here and read it out of the answer instead.
    out.extend_from_slice(&(FLAG_RD).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT: the OPT record below
    encode_name(name, &mut out)?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    // OPT: root name, type OPT, class = our UDP buffer, TTL = extended rcode 0, version 0, DO set.
    out.push(0x00);
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&EDNS_UDP_PAYLOAD.to_be_bytes());
    out.extend_from_slice(&0x0000_8000u32.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // RDLEN: no options
    Ok(out)
}

/// Write `name` in label form, terminated by the zero-length root label.
pub fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), BadName> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(BadName(name.to_string()));
    }
    let mut wire = 0usize;
    for label in trimmed.split('.') {
        let len = label.len();
        if len == 0 || len > 63 {
            return Err(BadName(name.to_string()));
        }
        out.push(len as u8);
        out.extend_from_slice(label.as_bytes());
        wire += len + 1;
    }
    out.push(0x00);
    wire += 1;
    if wire > 255 {
        return Err(BadName(name.to_string()));
    }
    Ok(())
}

/// Read a possibly compressed name at `pos`, returning the presentation name and the offset just past
/// the name *in this record stream* (a compression pointer is 2 bytes and ends the name here).
pub fn decode_name(msg: &[u8], pos: usize) -> Result<(String, usize), DecodeError> {
    let mut name = String::new();
    let mut p = pos;
    let mut end = None;
    // Every pointer must strictly decrease the offset (RFC 1035 §4.1.4), so the walk is bounded; count
    // anyway so a hostile message cannot spin us.
    let mut hops = 0;
    loop {
        let len = *msg.get(p).ok_or(DecodeError::Truncated)? as usize;
        if len & 0xc0 == 0xc0 {
            let lo = *msg.get(p + 1).ok_or(DecodeError::Truncated)? as usize;
            let target = ((len & 0x3f) << 8) | lo;
            if end.is_none() {
                end = Some(p + 2);
            }
            hops += 1;
            if target >= p || hops > 64 {
                return Err(DecodeError::CompressionLoop);
            }
            p = target;
            continue;
        }
        if len & 0xc0 != 0 {
            // 0x40 / 0x80 label types are not defined in RFC 1035 and were never widely deployed.
            return Err(DecodeError::Truncated);
        }
        if len == 0 {
            if end.is_none() {
                end = Some(p + 1);
            }
            return Ok((name, end.unwrap_or(p + 1)));
        }
        let bytes = msg.get(p + 1..p + 1 + len).ok_or(DecodeError::Truncated)?;
        if !name.is_empty() {
            name.push('.');
        }
        // A label byte may be any octet; escape the ones that would otherwise be read as structure.
        for &b in bytes {
            match b {
                b'.' | b'\\' => {
                    name.push('\\');
                    name.push(b as char);
                }
                0x20..=0x7e => name.push(b as char),
                other => name.push_str(&format!("\\{other:03}")),
            }
        }
        p += 1 + len;
    }
}

/// One address answer with the TTL it may be cached for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRecord {
    pub addr: IpAddr,
    pub ttl: u32,
}

/// Everything a client needs from a response: the addresses (following any CNAME chain), the rcode, and
/// whether the resolver signed off on the data with AD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The addresses for the queried name, in the order the resolver returned them.
    pub addrs: Vec<AddressRecord>,
    /// The response code: `RCODE_NOERROR`, `RCODE_SERVFAIL`, ...
    pub rcode: u8,
    /// AD: the resolver checked this data against a trust anchor.
    pub authenticated_data: bool,
    /// TC: the response was cut short and must be asked for again over TCP.
    pub truncated: bool,
}

/// The smallest TTL among the answer's records — the time the whole set stays fresh.
pub fn min_ttl(answer: &Answer) -> Option<u32> {
    answer.addrs.iter().map(|r| r.ttl).min()
}

fn be16(b: &[u8], at: usize) -> Result<u16, DecodeError> {
    let s = b.get(at..at + 2).ok_or(DecodeError::Truncated)?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], at: usize) -> Result<u32, DecodeError> {
    let s = b.get(at..at + 4).ok_or(DecodeError::Truncated)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Decode a response to the query we sent: check the id and the question, collect A/AAAA answers, follow
/// a CNAME inside the answer section, and report the rcode and the AD bit.
///
/// Only A and AAAA are collected; anything else in the answer section is skipped by its rdlength.
pub fn decode_answer(
    msg: &[u8],
    want_id: u16,
    want_name: &str,
    want_type: u16,
) -> Result<Answer, DecodeError> {
    if msg.len() < 12 {
        return Err(DecodeError::Truncated);
    }
    let id = be16(msg, 0)?;
    let flags = be16(msg, 2)?;
    if flags & FLAG_RESPONSE == 0 {
        return Err(DecodeError::NotAResponse);
    }
    if id != want_id {
        return Err(DecodeError::IdMismatch {
            got: id,
            want: want_id,
        });
    }
    let qdcount = be16(msg, 4)?;
    let ancount = be16(msg, 6)?;

    // The question has to be the one we asked: a response for another question is not our answer.
    let (qname, after_q) = decode_name(msg, 12)?;
    let qtype = be16(msg, after_q)?;
    let _qclass = be16(msg, after_q + 2)?;
    if qdcount != 1 || !qname.eq_ignore_ascii_case(want_name) || qtype != want_type {
        return Err(DecodeError::QuestionMismatch {
            got: qname,
            got_type: qtype,
            want: want_name.to_string(),
            want_type,
        });
    }

    let rcode = (flags & 0x000f) as u8;
    let mut answer = Answer {
        addrs: Vec::new(),
        rcode,
        authenticated_data: flags & FLAG_AD != 0,
        truncated: flags & FLAG_TC != 0,
    };
    if rcode != RCODE_NOERROR {
        return Ok(answer);
    }

    // Walk the answer section twice: once to collect addresses keyed by owner name, once to follow the
    // CNAME chain from the queried name to the name the addresses belong to.
    let mut addrs: Vec<(String, AddressRecord)> = Vec::new();
    let mut cnames: Vec<(String, String)> = Vec::new();
    let mut pos = after_q + 4;
    for _ in 0..ancount {
        let (owner, after_owner) = decode_name(msg, pos)?;
        let rtype = be16(msg, after_owner)?;
        let _class = be16(msg, after_owner + 2)?;
        let ttl = be32(msg, after_owner + 4)?;
        let rdlen = be16(msg, after_owner + 8)? as usize;
        let rdata_at = after_owner + 10;
        let rdata = msg
            .get(rdata_at..rdata_at + rdlen)
            .ok_or(DecodeError::ShortRecord)?;
        match rtype {
            TYPE_A if rdlen == 4 => {
                let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                addrs.push((
                    owner,
                    AddressRecord {
                        addr: IpAddr::V4(ip),
                        ttl,
                    },
                ));
            }
            TYPE_AAAA if rdlen == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                addrs.push((
                    owner,
                    AddressRecord {
                        addr: IpAddr::V6(Ipv6Addr::from(o)),
                        ttl,
                    },
                ));
            }
            TYPE_CNAME => {
                let (target, _) = decode_name(msg, rdata_at)?;
                cnames.push((owner, target));
            }
            _ => {}
        }
        pos = rdata_at + rdlen;
    }

    // Follow the chain: the queried name, then each CNAME target in turn (bounded by the number of
    // CNAMEs we actually saw, so a cycle terminates).
    let mut current = want_name.to_string();
    let mut hops = 0;
    loop {
        for (owner, rec) in &addrs {
            // A TTL of 0 is an answer that must not be cached, not an invalid one: the record still
            // says where the host is, so it is reported and the caller decides not to keep it.
            if owner.eq_ignore_ascii_case(&current) {
                answer.addrs.push(rec.clone());
            }
        }
        let next = cnames
            .iter()
            .find(|(from, _)| from.eq_ignore_ascii_case(&current))
            .map(|(_, to)| to.clone());
        hops += 1;
        match next {
            Some(to) if hops <= cnames.len() => current = to,
            _ => break,
        }
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-checked bytes: id 0x1234, RD set, QDCOUNT 1, ARCOUNT 1 (the OPT), example.com A.
    ///   12 34 | 01 00 | 00 01 | 00 00 | 00 00 | 00 01
    ///   07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 | 00 01 | 00 01
    ///   00 | 00 29 | 04 d0 | 00 00 80 00 | 00 00
    #[test]
    fn query_bytes_are_exactly_these() {
        let q = encode_query(0x1234, "example.com", TYPE_A).expect("a valid name encodes");
        assert_eq!(
            q,
            vec![
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, //
                0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
                0x00, //
                0x00, 0x01, 0x00, 0x01, //
                0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn the_do_bit_is_the_top_bit_of_the_opt_ttl() {
        let q = encode_query(1, "a.test", TYPE_A).expect("a valid name encodes");
        // The OPT TTL is the last 6 bytes of the message: 4 TTL, then RDLEN.
        let ttl = be32(&q, q.len() - 6).expect("the OPT TTL is there");
        assert_eq!(ttl, 0x0000_8000, "extended rcode 0, version 0, DO set");
    }

    #[test]
    fn a_trailing_dot_is_the_same_name() {
        assert_eq!(
            encode_name("example.com.", &mut vec![]),
            encode_name("example.com", &mut vec![])
        );
    }

    #[test]
    fn bad_names_are_rejected() {
        // Note "a.b." is absent: a trailing dot is the same name (asserted above), not a bad name.
        for bad in ["", ".", "a..b", &"x".repeat(64), &"a".repeat(64)] {
            assert!(
                encode_name(bad, &mut vec![]).is_err(),
                "{bad:?} should not encode"
            );
        }
        // 63 is the longest a label may be (RFC 1035 §2.3.4).
        assert!(encode_name(&"x".repeat(63), &mut vec![]).is_ok());
    }

    /// Build a response by hand: header, the question echoed, then records. Names are written
    /// uncompressed here so the expected bytes stay readable.
    fn response(id: u16, flags: u16, qname: &str, qtype: u16, records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(records.len() as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        encode_name(qname, &mut out).unwrap_or(());
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        for r in records {
            out.extend_from_slice(r);
        }
        out
    }

    fn record(name: &str, rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_name(name, &mut out).unwrap_or(());
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    #[test]
    fn a_record_round_trips_through_the_decoder() {
        let msg = response(
            0x4242,
            FLAG_RESPONSE | FLAG_AD,
            "example.com",
            TYPE_A,
            &[record("example.com", TYPE_A, 300, &[93, 184, 216, 34])],
        );
        let a = decode_answer(&msg, 0x4242, "example.com", TYPE_A)
            .expect("a well-formed response decodes");
        assert_eq!(a.rcode, RCODE_NOERROR);
        assert!(a.authenticated_data);
        assert!(!a.truncated);
        assert_eq!(a.addrs.len(), 1);
        assert_eq!(a.addrs[0].addr, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(min_ttl(&a), Some(300));
    }

    #[test]
    fn aaaa_and_the_ad_bit_off() {
        let mut rdata = [0u8; 16];
        rdata[0] = 0x26;
        rdata[1] = 0x06;
        rdata[15] = 1;
        let msg = response(
            1,
            FLAG_RESPONSE,
            "v6.test",
            TYPE_AAAA,
            &[record("v6.test", TYPE_AAAA, 60, &rdata)],
        );
        let a =
            decode_answer(&msg, 1, "v6.test", TYPE_AAAA).expect("a well-formed response decodes");
        assert!(
            !a.authenticated_data,
            "AD clear means the resolver did not sign off"
        );
        assert_eq!(a.addrs[0].addr, IpAddr::V6(Ipv6Addr::from(rdata)));
    }

    #[test]
    fn a_cname_inside_the_answer_is_followed() {
        let msg = response(
            7,
            FLAG_RESPONSE | FLAG_AD,
            "www.example.com",
            TYPE_A,
            &[
                record("www.example.com", TYPE_CNAME, 120, &{
                    let mut c = Vec::new();
                    encode_name("example.com", &mut c).unwrap_or(());
                    c
                }),
                record("example.com", TYPE_A, 90, &[1, 2, 3, 4]),
            ],
        );
        let a = decode_answer(&msg, 7, "www.example.com", TYPE_A)
            .expect("a well-formed response decodes");
        assert_eq!(a.addrs.len(), 1);
        assert_eq!(a.addrs[0].addr, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(
            min_ttl(&a),
            Some(90),
            "the address is what we cache, so its TTL is the one that counts"
        );
    }

    /// A compressed pointer: "example.com" appears in full at the question, and the answer's owner is a
    /// pointer back to it (RFC 1035 §4.1.4).
    #[test]
    fn compressed_names_are_resolved() {
        let mut msg = response(9, FLAG_RESPONSE | FLAG_AD, "example.com", TYPE_A, &[]);
        let at = 12; // where "example.com" starts, inside the question
        msg.extend_from_slice(&[0xc0, at as u8]);
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&45u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[5, 6, 7, 8]);
        msg[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1

        let a =
            decode_answer(&msg, 9, "example.com", TYPE_A).expect("a well-formed response decodes");
        assert_eq!(a.addrs.len(), 1);
        assert_eq!(a.addrs[0].addr, IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
    }

    /// A TTL of 0 is still an answer: the record is reported so the caller can use it once, and the
    /// cache (which keys off the TTL) simply will not keep it.
    #[test]
    fn a_zero_ttl_record_is_still_an_answer() {
        let msg = response(
            11,
            FLAG_RESPONSE | FLAG_AD,
            "short.test",
            TYPE_A,
            &[record("short.test", TYPE_A, 0, &[10, 0, 0, 1])],
        );
        let a =
            decode_answer(&msg, 11, "short.test", TYPE_A).expect("a well-formed response decodes");
        assert_eq!(a.addrs.len(), 1);
        assert_eq!(a.addrs[0].addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(a.addrs[0].ttl, 0);
        assert_eq!(
            min_ttl(&a),
            Some(0),
            "and it is this that keeps it out of the cache"
        );
    }

    #[test]
    fn servfail_carries_the_rcode_and_clears_ad() {
        // The rcode lives in the low 4 bits of the flags word, so it goes into the flags we build.
        let msg = response(
            3,
            FLAG_RESPONSE | RCODE_SERVFAIL as u16,
            "bogus.test",
            TYPE_A,
            &[],
        );
        let a =
            decode_answer(&msg, 3, "bogus.test", TYPE_A).expect("a well-formed response decodes");
        assert_eq!(a.rcode, RCODE_SERVFAIL);
        assert!(a.addrs.is_empty());
        assert!(!a.authenticated_data);
    }

    #[test]
    fn truncation_is_read_from_bit_9() {
        let msg = response(4, FLAG_RESPONSE | FLAG_TC, "big.test", TYPE_A, &[]);
        assert!(
            decode_answer(&msg, 4, "big.test", TYPE_A)
                .expect("a well-formed response decodes")
                .truncated
        );
        // And the neighbouring bits must not set it: AD (bit 5) and RD (bit 8).
        let msg = response(
            4,
            FLAG_RESPONSE | FLAG_AD | FLAG_RD,
            "big.test",
            TYPE_A,
            &[],
        );
        assert!(
            !decode_answer(&msg, 4, "big.test", TYPE_A)
                .expect("a well-formed response decodes")
                .truncated
        );
    }

    #[test]
    fn a_response_for_another_id_or_question_is_refused() {
        let msg = response(4, FLAG_RESPONSE | FLAG_AD, "example.com", TYPE_A, &[]);
        assert!(matches!(
            decode_answer(&msg, 5, "example.com", TYPE_A),
            Err(DecodeError::IdMismatch { .. })
        ));
        assert!(matches!(
            decode_answer(&msg, 4, "other.example", TYPE_A),
            Err(DecodeError::QuestionMismatch { .. })
        ));
        assert!(matches!(
            decode_answer(&msg, 4, "example.com", TYPE_AAAA),
            Err(DecodeError::QuestionMismatch { .. })
        ));
    }

    #[test]
    fn a_query_is_not_a_response_and_short_messages_are_refused() {
        let q = encode_query(1, "example.com", TYPE_A).expect("a valid name encodes");
        assert_eq!(
            decode_answer(&q, 1, "example.com", TYPE_A),
            Err(DecodeError::NotAResponse)
        );
        assert_eq!(
            decode_answer(&[0, 1, 2], 1, "a.test", TYPE_A),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn a_compression_pointer_must_go_backwards() {
        // One answer whose owner name is a pointer to itself: legal-looking bytes, an endless walk.
        let mut msg = response(1, FLAG_RESPONSE, "a.test", TYPE_A, &[]);
        let at = msg.len(); // where the answer section starts
        msg.extend_from_slice(&[0xc0, (at & 0xff) as u8]); // owner = a pointer back to `at`
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&30u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[1, 2, 3, 4]);
        msg[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
        assert_eq!(
            decode_answer(&msg, 1, "a.test", TYPE_A),
            Err(DecodeError::CompressionLoop)
        );
    }

    #[test]
    fn an_escaped_label_round_trips() {
        let mut buf = Vec::new();
        encode_name("a.b", &mut buf).unwrap_or(());
        assert_eq!(decode_name(&buf, 0).map(|(n, _)| n), Ok("a.b".to_string()));
    }
}
