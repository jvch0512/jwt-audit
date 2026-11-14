//! jwt-audit: decode JWTs (no signature check) and report risky settings.
pub mod json;

use json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub severity: &'static str,
    pub rule: &'static str,
    pub where_: String,
    pub message: String,
}

pub fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

/// base64url decode, padding optional. Returns None on any invalid character.
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if s.trim_end_matches('=').len() % 4 == 1 {
        return None;
    }
    Some(out)
}

fn decode_part(p: &str) -> Result<Value, String> {
    let bytes = b64url_decode(p).ok_or("not base64url")?;
    let text = String::from_utf8(bytes).map_err(|_| "not utf-8".to_string())?;
    let v = json::parse(&text)?;
    match v {
        Value::Obj(_) => Ok(v),
        _ => Err("not a JSON object".into()),
    }
}

const SECRET_WORDS: [&str; 9] = ["password", "passwd", "secret", "api_key", "apikey", "private_key", "ssn", "credit", "card_number"];

fn push(fs: &mut Vec<Finding>, severity: &'static str, rule: &'static str, w: &str, message: String) {
    fs.push(Finding { severity, rule, where_: w.to_string(), message });
}

/// Audit one token. `line` is the 1-based line number, `now` a Unix time in seconds.
pub fn audit_token(line: usize, token: &str, now: i64) -> Vec<Finding> {
    let mut fs = Vec::new();
    let parts: Vec<&str> = token.split('.').collect();
    let w0 = format!("line {}", line);
    if parts.len() != 3 {
        push(&mut fs, "info", "JWT009", &w0, "not a JWT: expected three dot separated parts".into());
        return fs;
    }
    let header = match decode_part(parts[0]) {
        Ok(h) => h,
        Err(e) => {
            push(&mut fs, "info", "JWT009", &w0, format!("header could not be decoded: {}", e));
            return fs;
        }
    };
    let payload = match decode_part(parts[1]) {
        Ok(p) => p,
        Err(e) => {
            push(&mut fs, "info", "JWT009", &w0, format!("payload could not be decoded: {}", e));
            return fs;
        }
    };
    let alg = header.get("alg").and_then(|a| a.as_str()).unwrap_or("").to_string();
    let w = format!("line {} (alg={})", line, if alg.is_empty() { "missing" } else { &alg });

    if alg.is_empty() || alg.eq_ignore_ascii_case("none") {
        push(&mut fs, "critical", "JWT001", &w, "no signature algorithm: any token can be forged".into());
    }
    for k in ["jku", "x5u", "jwk"] {
        if header.get(k).is_some() {
            push(&mut fs, "high", "JWT002", &w, format!("'{}' header lets the token point at its own verification key; ignore it and use a fixed key set", k));
        }
    }
    if let Some(kid) = header.get("kid").and_then(|k| k.as_str()) {
        if kid.contains("..") || kid.contains('/') || kid.contains('\\') || kid.contains('\'') || kid.contains(';') || kid.contains('|') || kid.contains('`') {
            push(&mut fs, "high", "JWT003", &w, "'kid' contains path, SQL or shell characters: classic injection vector".into());
        }
    }
    if matches!(alg.as_str(), "HS256" | "HS384" | "HS512") {
        push(&mut fs, "medium", "JWT006", &w, format!("{} uses a shared secret: weak secrets can be brute forced offline, and RSA keys must never be accepted as HMAC secrets", alg));
    }

    let exp = payload.get("exp").and_then(|v| v.as_f64());
    let iat = payload.get("iat").and_then(|v| v.as_f64());
    match exp {
        None => push(&mut fs, "high", "JWT004", &w, "no 'exp' claim: the token never expires".into()),
        Some(e) => {
            if let Some(i) = iat {
                let life = e - i;
                if life > 30.0 * 86400.0 {
                    push(&mut fs, "high", "JWT004", &w, format!("lifetime of {:.0} days is far too long for a bearer token", life / 86400.0));
                } else if life > 86400.0 {
                    push(&mut fs, "medium", "JWT005", &w, format!("lifetime of {:.1} days: prefer minutes or hours with a refresh token", life / 86400.0));
                }
            }
            if e < now as f64 {
                push(&mut fs, "medium", "JWT005", &w, format!("expired {} seconds before --now", now as i64 - e as i64));
            }
        }
    }
    let mut missing = Vec::new();
    if payload.get("aud").is_none() {
        missing.push("aud");
    }
    if payload.get("iss").is_none() {
        missing.push("iss");
    }
    if !missing.is_empty() {
        push(&mut fs, "medium", "JWT007", &w, format!("missing {}: a token for another service or issuer would be accepted", missing.join(" and ")));
    }
    let mut bad: Vec<String> = payload
        .keys()
        .into_iter()
        .filter(|k| {
            let l = k.to_ascii_lowercase();
            SECRET_WORDS.iter().any(|s| l.contains(s))
        })
        .map(|k| k.to_string())
        .collect();
    bad.sort();
    if !bad.is_empty() {
        push(&mut fs, "high", "JWT008", &w, format!("payload is readable by anyone and contains claim names that look like secrets: {}", bad.join(", ")));
    }
    fs
}

pub fn audit_lines(text: &str, now: i64) -> (usize, Vec<Finding>) {
    let mut n = 0;
    let mut fs = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let t = raw.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        n += 1;
        fs.extend(audit_token(i + 1, t, now));
    }
    fs.sort_by(|a, b| sev_rank(a.severity).cmp(&sev_rank(b.severity)).then_with(|| a.where_.cmp(&b.where_)).then_with(|| a.rule.cmp(b.rule)));
    (n, fs)
}
