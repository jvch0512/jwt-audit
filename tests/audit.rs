use jwt_audit::json::{self, Value};
use jwt_audit::{audit_lines, audit_token, b64url_decode, Finding};
use std::io::Write;
use std::process::{Command, Stdio};

const NOW: i64 = 1_763_100_000;

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.len();
        let v = ((chunk[0] as u32) << 16) | ((*chunk.get(1).unwrap_or(&0) as u32) << 8) | (*chunk.get(2).unwrap_or(&0) as u32);
        for k in 0..=n {
            out.push(T[((v >> (18 - 6 * k)) & 63) as usize] as char);
        }
    }
    out
}
fn tok(h: &str, p: &str) -> String {
    format!("{}.{}.sig", b64(h.as_bytes()), b64(p.as_bytes()))
}
fn good_payload() -> String {
    format!(r#"{{"iss":"i","aud":"a","sub":"u","iat":{},"exp":{}}}"#, NOW - 60, NOW + 3000)
}
fn audit(h: &str, p: &str) -> Vec<Finding> {
    audit_token(1, &tok(h, p), NOW)
}
fn has(fs: &[Finding], rule: &str, sev: &str) -> bool {
    fs.iter().any(|f| f.rule == rule && f.severity == sev)
}
fn rules(fs: &[Finding]) -> Vec<&'static str> {
    let mut r: Vec<&'static str> = fs.iter().map(|f| f.rule).collect();
    r.sort();
    r.dedup();
    r
}

#[test]
fn b64_roundtrip_and_errors() {
    for s in ["", "a", "ab", "abc", "abcd", "hello world!"] {
        assert_eq!(b64url_decode(&b64(s.as_bytes())).unwrap(), s.as_bytes());
    }
    assert_eq!(b64url_decode("YQ==").unwrap(), b"a");
    assert!(b64url_decode("a+b").is_none());
    assert!(b64url_decode("a").is_none());
    assert!(b64url_decode("a b").is_none());
}

#[test]
fn json_parser() {
    assert_eq!(json::parse("null").unwrap(), Value::Null);
    assert_eq!(json::parse(" true ").unwrap(), Value::Bool(true));
    assert_eq!(json::parse("-1.5e2").unwrap(), Value::Num(-150.0));
    assert_eq!(json::parse(r#""a\né\"""#).unwrap(), Value::Str("a\né\"".into()));
    let v = json::parse(r#"{"a":[1,2,{"b":null}],"c":"d"}"#).unwrap();
    assert_eq!(v.get("c").unwrap().as_str(), Some("d"));
    assert_eq!(v.keys(), vec!["a", "c"]);
    assert!(json::parse("{").is_err());
    assert!(json::parse(r#"{"a":1,}"#).is_err());
    assert!(json::parse("[1,2").is_err());
    assert!(json::parse(r#"{"a" 1}"#).is_err());
    assert!(json::parse("{1:2}").is_err());
    assert!(json::parse("tru").is_err());
    assert!(json::parse("1 2").is_err());
    assert!(json::parse("\"a\u{1}\"").is_err());
    assert!(json::parse(r#""\x""#).is_err());
}

#[test]
fn json_depth_limit() {
    let deep = "[".repeat(200) + &"]".repeat(200);
    assert!(json::parse(&deep).is_err());
    let ok = "[".repeat(10) + &"]".repeat(10);
    assert!(json::parse(&ok).is_ok());
}

#[test]
fn clean_token_has_no_findings() {
    assert!(audit(r#"{"alg":"RS256","typ":"JWT","kid":"key-1"}"#, &good_payload()).is_empty());
    assert!(audit(r#"{"alg":"ES256"}"#, &good_payload()).is_empty());
}

#[test]
fn alg_none_variants() {
    for a in ["none", "None", "NONE"] {
        let fs = audit(&format!(r#"{{"alg":"{}"}}"#, a), &good_payload());
        assert!(has(&fs, "JWT001", "critical"), "{}", a);
    }
    assert!(has(&audit(r#"{"typ":"JWT"}"#, &good_payload()), "JWT001", "critical"));
    assert!(has(&audit(r#"{"alg":""}"#, &good_payload()), "JWT001", "critical"));
}

#[test]
fn key_injection_headers() {
    for h in ["jku", "x5u", "jwk"] {
        let fs = audit(&format!(r#"{{"alg":"RS256","{}":"x"}}"#, h), &good_payload());
        assert!(has(&fs, "JWT002", "high"), "{}", h);
    }
}

#[test]
fn kid_injection() {
    for k in ["../../etc/passwd", "a/b", "a'b", "a;b", "a|b", "a`b", "a\\\\b"] {
        let fs = audit(&format!(r#"{{"alg":"RS256","kid":"{}"}}"#, k), &good_payload());
        assert!(has(&fs, "JWT003", "high"), "{}", k);
    }
    assert!(!has(&audit(r#"{"alg":"RS256","kid":"2025-key_1"}"#, &good_payload()), "JWT003", "high"));
}

#[test]
fn hmac_algorithms() {
    for a in ["HS256", "HS384", "HS512"] {
        assert!(has(&audit(&format!(r#"{{"alg":"{}"}}"#, a), &good_payload()), "JWT006", "medium"));
    }
    assert!(!has(&audit(r#"{"alg":"RS256"}"#, &good_payload()), "JWT006", "medium"));
}

#[test]
fn expiry_rules() {
    let h = r#"{"alg":"RS256"}"#;
    assert!(has(&audit(h, r#"{"iss":"i","aud":"a"}"#), "JWT004", "high"));
    let long = format!(r#"{{"iss":"i","aud":"a","iat":{},"exp":{}}}"#, NOW, NOW + 40 * 86400);
    assert!(has(&audit(h, &long), "JWT004", "high"));
    let mid = format!(r#"{{"iss":"i","aud":"a","iat":{},"exp":{}}}"#, NOW, NOW + 3 * 86400);
    assert!(has(&audit(h, &mid), "JWT005", "medium"));
    let boundary = format!(r#"{{"iss":"i","aud":"a","iat":{},"exp":{}}}"#, NOW, NOW + 86400);
    assert!(!has(&audit(h, &boundary), "JWT005", "medium"));
    let expired = format!(r#"{{"iss":"i","aud":"a","iat":{},"exp":{}}}"#, NOW - 7200, NOW - 3600);
    let fs = audit(h, &expired);
    assert!(has(&fs, "JWT005", "medium"));
    assert!(fs.iter().any(|f| f.message.contains("3600 seconds")));
    let no_iat = format!(r#"{{"iss":"i","aud":"a","exp":{}}}"#, NOW + 99 * 86400);
    assert!(audit(h, &no_iat).is_empty());
}

#[test]
fn audience_and_issuer() {
    let h = r#"{"alg":"RS256"}"#;
    let p = |extra: &str| format!(r#"{{{}"iat":{},"exp":{}}}"#, extra, NOW - 1, NOW + 100);
    assert!(audit(h, &p(r#""iss":"i","aud":"a","#)).is_empty());
    let fs = audit(h, &p(r#""iss":"i","#));
    assert!(has(&fs, "JWT007", "medium") && fs[0].message.contains("missing aud"));
    let fs = audit(h, &p(r#""aud":"a","#));
    assert!(fs[0].message.contains("missing iss"));
    assert!(audit(h, &p("")).iter().any(|f| f.message.contains("aud and iss")));
}

#[test]
fn secret_claim_names_without_values() {
    let p = format!(r#"{{"iss":"i","aud":"a","iat":{},"exp":{},"Password":"hunter2-value","apiKey":"k-value","note":"fine"}}"#, NOW - 1, NOW + 60);
    let fs = audit(r#"{"alg":"RS256"}"#, &p);
    assert!(has(&fs, "JWT008", "high"));
    let all: String = fs.iter().map(|f| format!("{} {}", f.where_, f.message)).collect();
    assert!(all.contains("Password") && all.contains("apiKey"));
    assert!(!all.contains("hunter2-value") && !all.contains("k-value"));
}

#[test]
fn malformed_tokens() {
    for (t, rule) in [("a.b", "JWT009"), ("a.b.c.d", "JWT009"), ("!!!.e30.x", "JWT009"), ("e30.!!!.x", "JWT009"), ("", "JWT009")] {
        let fs = audit_token(3, t, NOW);
        assert_eq!(fs.len(), 1, "{}", t);
        assert_eq!(fs[0].rule, rule);
        assert_eq!(fs[0].severity, "info");
    }
    let arr = format!("{}.{}.s", b64(b"[1]"), b64(b"{}"));
    assert_eq!(audit_token(1, &arr, NOW)[0].rule, "JWT009");
}

#[test]
fn token_text_never_in_output() {
    let t = tok(r#"{"alg":"none"}"#, r#"{"sub":"very-secret-subject"}"#);
    let fs = audit_token(1, &t, NOW);
    let all: String = fs.iter().map(|f| format!("{}{}", f.where_, f.message)).collect();
    assert!(!all.contains(&t) && !all.contains("very-secret-subject"));
}

#[test]
fn lines_are_sorted_and_counted() {
    let text = format!("# comment\n\n{}\n{}\n", tok(r#"{"alg":"HS256"}"#, &good_payload()), tok(r#"{"alg":"none"}"#, &good_payload()));
    let (n, fs) = audit_lines(&text, NOW);
    assert_eq!(n, 2);
    assert_eq!(fs[0].rule, "JWT001");
    assert_eq!(fs[0].where_, "line 4 (alg=none)");
    assert_eq!(rules(&fs), vec!["JWT001", "JWT006"]);
}

fn cli(args: &[&str], stdin: Option<&str>) -> (i32, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_jwt-audit"));
    c.args(args).stdout(Stdio::piped()).stderr(Stdio::null());
    if stdin.is_some() {
        c.stdin(Stdio::piped());
    }
    let mut child = c.spawn().unwrap();
    if let Some(s) = stdin {
        child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).to_string())
}
const SAMPLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/tokens.txt");

#[test]
fn cli_exit_codes() {
    assert_eq!(cli(&[SAMPLE, "--now", "1763100000"], None).0, 0);
    assert_eq!(cli(&[SAMPLE, "--now", "1763100000", "--fail-on", "critical"], None).0, 1);
    assert_eq!(cli(&[SAMPLE, "--now", "1763100000", "--fail-on", "high"], None).0, 1);
    assert_eq!(cli(&["/no/such/file"], None).0, 2);
    assert_eq!(cli(&[], None).0, 2);
    assert_eq!(cli(&[SAMPLE, "--bogus"], None).0, 2);
    assert_eq!(cli(&[SAMPLE, "--now", "abc"], None).0, 2);
    assert_eq!(cli(&[SAMPLE, "--fail-on", "nope"], None).0, 2);
}

#[test]
fn cli_stdin_and_tsv() {
    let t = tok(r#"{"alg":"none"}"#, &good_payload());
    let (code, out) = cli(&["-", "--tsv", "--now", "1763100000", "--fail-on", "critical"], Some(&t));
    assert_eq!(code, 1);
    assert!(out.starts_with("# 1 tokens, 1 findings\ncritical\tJWT001\tline 1 (alg=none)\t"));
    let (code, _) = cli(&["-", "--now", "1763100000", "--fail-on", "medium"], Some(&tok(r#"{"alg":"ES256"}"#, &good_payload())));
    assert_eq!(code, 0);
}
