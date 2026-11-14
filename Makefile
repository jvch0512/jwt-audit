build:
	cargo build --release

test:
	cargo test --release

sample: build
	mkdir -p docs site
	./target/release/jwt-audit examples/tokens.txt --now 1763100000 > docs/sample-output.txt; true
	./target/release/jwt-audit examples/tokens.txt --now 1763100000 --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "jwt-audit" "Audits JSON Web Tokens for alg none, key injection headers, missing expiry and secrets in claims. Rust." "Tokens built from invented claims and a fake signature."
