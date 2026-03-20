.PHONY: build test clean curl-smoke ls-smoke openssl-smoke curl-fuzz ls-fuzz openssl-fuzz curl-long ls-long openssl-long curl-servers curl-report openssl-report ls-report test-openssl curl-reseed curl-evil-smoke curl-both-smoke test-servers

# Build
build:
	cargo build --release

build-debug:
	cargo build

# Test
test:
	cargo test

test-curl:
	cargo test -p curl-fuzzer

test-ls:
	cargo test -p ls-fuzzer

test-ga:
	cargo test -p ga-engine

test-openssl:
	cargo test -p openssl-fuzzer

# Smoke tests (quick sanity check)
curl-smoke:
	cargo run --release -p curl-fuzzer -- run \
		--no-servers \
		--population-size 10 \
		--generations 5

ls-smoke:
	cargo run --release -p ls-fuzzer -- run \
		--population-size 10 \
		--generations 5

openssl-smoke:
	cargo run --release -p openssl-fuzzer -- run \
		--population-size 10 \
		--generations 5

# Development runs (~1-2 hours for curl, ~5 min for ls)
curl-fuzz:
	cargo run --release -p curl-fuzzer -- run \
		--population-size 50 \
		--generations 20000 \
		--mutation-rate 0.05 \
		--crossover-rate 0.4 \
		--max-active-flags 32 \
		--curl-path /usr/local/bin/curl \
		--exclude-flag doh-url \
		--dict etc/blns.txt --dict etc/AFLplusplus/dictionaries/http.dict --dict etc/AFLplusplus/dictionaries/ftp.dict --dict etc/AFLplusplus/dictionaries/utf8.dict --dict etc/AFLplusplus/dictionaries/url.dict

ls-fuzz:
	cargo run --release -p ls-fuzzer -- run \
		--population-size 50 \
		--generations 100 \
		--mutation-rate 0.05 \
		--crossover-rate 0.4

openssl-fuzz:
	cargo run --release -p openssl-fuzzer -- run \
		--population-size 50 \
		--generations 20000

openssl-enc-fuzz:
	cargo run --release -p openssl-fuzzer -- run \
		--subcommand enc \
		--population-size 50 \
		--generations 10000

openssl-x509-fuzz:
	cargo run --release -p openssl-fuzzer -- run \
		--subcommand x509 \
		--population-size 50 \
		--generations 10000

openssl-cms-fuzz:
	cargo run --release -p openssl-fuzzer -- run \
		--subcommand cms \
		--population-size 50 \
		--generations 10000

openssl-asn1parse-fuzz:
	cargo run --release -p openssl-fuzzer -- run \
		--subcommand asn1parse \
		--population-size 50 \
		--generations 10000

# Long-running sessions (overnight / weekend)
curl-long:
	cargo run --release -p curl-fuzzer -- run \
		--population-size 250 \
		--generations 500 \
		--mutation-rate 0.05 \
		--crossover-rate 0.4 \
		--max-active-flags 45 \
		--timeout-ms 2000 \
		--curl-path /usr/local/bin/curl \
		--dict etc/blns.txt --dict etc/AFLplusplus/dictionaries/http.dict --dict etc/AFLplusplus/dictionaries/ftp.dict --dict etc/AFLplusplus/dictionaries/utf8.dict --dict etc/AFLplusplus/dictionaries/url.dict

ls-long:
	cargo run --release -p ls-fuzzer -- run \
		--population-size 100 \
		--generations 500 \
		--mutation-rate 0.05 \
		--crossover-rate 0.4 \
		--max-active-flags 20

openssl-long:
	cargo run --release -p openssl-fuzzer -- run \
		--population-size 250 \
		--generations 500

# Seeded runs — resume from previous findings
curl-reseed:
	cargo run --release -p curl-fuzzer -- run \
		--seed-db curl-fuzzer.db \
		--population-size 50 \
		--generations 100 \
		--mutation-rate 0.05 \
		--crossover-rate 0.4 \
		--max-active-flags 22 \
		--curl-path /usr/local/bin/curl \
		--dict etc/blns.txt --dict etc/AFLplusplus/dictionaries/http.dict --dict etc/AFLplusplus/dictionaries/ftp.dict --dict etc/AFLplusplus/dictionaries/utf8.dict --dict etc/AFLplusplus/dictionaries/url.dict

curl-reseed-long:
	cargo run --release -p curl-fuzzer -- run \
		--seed-db curl-fuzzer.db \
		--population-size 250 \
		--generations 500 \
		--mutation-rate 0.05 \
		--crossover-rate 0.4 \
		--max-active-flags 45 \
		--curl-path /usr/local/bin/curl \
		--dict etc/blns.txt --dict etc/AFLplusplus/dictionaries/http.dict --dict etc/AFLplusplus/dictionaries/ftp.dict --dict etc/AFLplusplus/dictionaries/utf8.dict --dict etc/AFLplusplus/dictionaries/url.dict

# Start test servers standalone
curl-servers:
	cargo run --release -p curl-fuzzer -- servers

# Reports
curl-report:
	cargo run --release -p curl-fuzzer -- report --top 20

ls-report:
	cargo run --release -p ls-fuzzer -- report --top 20

openssl-report:
	cargo run --release -p openssl-fuzzer -- report --top 20

# Evil server smoke tests
curl-evil-smoke:
	cargo run --release -p curl-fuzzer -- run \
		--generations 3 \
		--population-size 10 \
		--server-mode evil \
		--timeout-ms 5000 \
		--protocols http,ftp,smtp

curl-both-smoke:
	cargo run --release -p curl-fuzzer -- run \
		--generations 3 \
		--population-size 10 \
		--server-mode both \
		--timeout-ms 5000 \
		--protocols http,ftp,smtp

# Python server tests
test-servers:
	python3 -m pytest test-servers/ -v

# Clean
clean:
	cargo clean
