use jwt_audit::{audit_lines, sev_rank};
use std::io::Read;
use std::process::exit;

fn usage() -> ! {
    eprintln!("usage: jwt-audit FILE|- [--tsv] [--now UNIX_TIME] [--fail-on medium|high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.");
    exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut path: Option<String> = None;
    let mut tsv = false;
    let mut now: Option<i64> = None;
    let mut fail: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--tsv" => tsv = true,
            "--now" => {
                i += 1;
                now = args.get(i).and_then(|v| v.parse().ok());
                if now.is_none() {
                    usage();
                }
            }
            "--fail-on" => {
                i += 1;
                match args.get(i).map(|s| s.as_str()) {
                    Some(v @ ("medium" | "high" | "critical")) => fail = Some(v.to_string()),
                    _ => usage(),
                }
            }
            a if a.starts_with('-') && a != "-" => usage(),
            a => {
                if path.is_some() {
                    usage();
                }
                path = Some(a.to_string());
            }
        }
        i += 1;
    }
    let path = path.unwrap_or_else(|| usage());
    let text = if path == "-" {
        let mut s = String::new();
        if std::io::stdin().read_to_string(&mut s).is_err() {
            eprintln!("error: cannot read standard input");
            exit(2);
        }
        s
    } else {
        match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => {
                eprintln!("error: cannot read {}", path);
                exit(2);
            }
        }
    };
    let now = now.unwrap_or_else(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
    });
    let (n, fs) = audit_lines(&text, now);
    if tsv {
        println!("# {} tokens, {} findings", n, fs.len());
        for f in &fs {
            println!("{}\t{}\t{}\t{}", f.severity, f.rule, f.where_, f.message);
        }
    } else {
        println!("{} tokens, {} findings", n, fs.len());
        for f in &fs {
            println!("{:<8} {} {}\n         {}", f.severity.to_uppercase(), f.rule, f.where_, f.message);
        }
    }
    let floor = match fail.as_deref() {
        Some("critical") => 0,
        Some("high") => 1,
        Some("medium") => 2,
        _ => -1,
    };
    if floor >= 0 && fs.iter().any(|f| (sev_rank(f.severity) as i32) <= floor) {
        exit(1);
    }
}
