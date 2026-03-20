# curl-fuzz-deux

A genetic algorithm fuzzing framework. Uses evolutionary computing to explore combinatorial flag spaces of command-line tools, finding crashes, hangs, memory issues, and unexpected behavior.

Currently includes three fuzzer targets:
- **curl-fuzzer** — fuzzes [curl](https://curl.se/) across 200+ flags and 20 protocols
- **ls-fuzzer** — fuzzes the Unix `ls` command across 55 flags
- **openssl-fuzzer** — fuzzes `openssl s_client` TLS handshakes against an ASan-instrumented OpenSSL build

## Quick Start

```bash
# Build everything
make build

# Run tests
make test

# Quick smoke tests
make curl-smoke
make ls-smoke
make openssl-smoke

# Full fuzzing runs
make curl-fuzz
make ls-fuzz
make openssl-fuzz
```

Or run directly:

```bash
# curl fuzzer
cargo run -p curl-fuzzer -- run --no-servers --generations 5 --population-size 10

# ls fuzzer
cargo run -p ls-fuzzer -- run --generations 5 --population-size 10

# openssl fuzzer
cargo run -p openssl-fuzzer -- run --generations 5 --population-size 10
```

## Architecture

Cargo workspace with a shared GA engine and per-target fuzzer crates:

```
curl-fuzz-deux/
├── ga-engine/              # Generic GA library (traits, engine, selection, crossover, mutation)
├── curl-fuzzer/            # Curl-specific fuzzer (binary + library)
├── ls-fuzzer/              # ls-specific fuzzer (binary)
├── openssl-fuzzer/         # OpenSSL s_client fuzzer (binary + library)
├── config/
│   ├── curl-default.toml   # GA + curl-fuzzer configuration
│   ├── curl-flags.toml     # Flag metadata overlay + protocol affinity
│   ├── openssl-default.toml # OpenSSL fuzzer configuration
│   └── openssl-flags.toml  # OpenSSL flag metadata overlay
├── test-servers/           # Python test servers for curl/openssl fuzzing
├── curl-findings/          # Output: curl-fuzzer reproducible scripts (gitignored)
├── ls-findings/            # Output: ls-fuzzer reproducible scripts (gitignored)
├── openssl-findings/       # Output: openssl-fuzzer reproducible scripts (gitignored)
└── docs/                   # Design specs and implementation plans
```

### ga-engine

A generic genetic algorithm library with pluggable traits:

- `Individual` — chromosome representation
- `FitnessEvaluator` — scoring function
- `CrossoverOperator` — parent recombination
- `MutationOperator` — random variation
- `SelectionStrategy` — parent selection (tournament, roulette, rank)
- `RateControl` — dynamic mutation rate adjustment
- `AdaptiveMutationRate` — stagnation detection with hypermutation spikes
- `DiversityConfig` — population diversity monitoring with random immigrant injection

Any new fuzzer target just implements these traits and reuses the engine.

#### Adaptive Mutation & Diversity

The engine includes built-in stagnation escape mechanisms:

- **Adaptive mutation rate**: Tracks best fitness over a sliding window. When improvement stalls (<1% over 5 generations), spikes mutation rate to 5x base for 3 generations, then decays back. All fuzzers use this automatically.
- **Diversity monitoring**: Measures population diversity as the ratio of unique flag activation patterns. When diversity drops below 30%, replaces the worst 20% of the population with freshly randomized individuals ("random immigrants"). Prevents premature convergence.
- **Progress output** shows both metrics: `div=72% rate=0.050` or `div=28% rate=0.250 SPIKE`.

### curl-fuzzer

Fuzzes curl with 17 fitness signals, 20 protocol support, per-protocol baselines, and Python test servers.

| Module | Purpose |
|--------|---------|
| `flag_parser.rs` | Auto-discover flags from `curl --help all` |
| `flag_overlay.rs` | Load curated flag metadata from TOML |
| `flag_seeds.rs` | Auto-enrich flags with seed values |
| `individual.rs` | `CurlIndividual` with protocol-aware chromosome |
| `executor.rs` | Spawn curl, capture exit/signal/timing/RSS/FDs |
| `fitness.rs` | 17-signal weighted fitness scoring |
| `protocol.rs` | Protocol registry (20 protocols, URL templates, server spawn config) |
| `servers.rs` | Python test server lifecycle management |
| `verbose_state.rs` | Parse `curl --verbose` output for state machine anomalies |
| `coverage.rs` | Coverage edge tracking (for future instrumentation) |
| `persistence.rs` | SQLite results storage |
| `findings.rs` | Write reproducible .sh scripts |
| `config.rs` | TOML config + CLI override merging |

### ls-fuzzer

Fuzzes ls with auto-generated test fixtures (symlinks, special characters, deep directories, many files).

| Module | Purpose |
|--------|---------|
| `flags.rs` | 55 known ls flags with value types |
| `individual.rs` | `LsIndividual` with flag chromosome |
| `executor.rs` | Spawn ls, capture exit/signal/timing |
| `fitness.rs` | Crash, exit code, stderr, timing, output size scoring |
| `persistence.rs` | SQLite results storage |
| `findings.rs` | Write reproducible .sh scripts |
| `test_fixtures.rs` | Create diverse filesystem structures for testing |

### openssl-fuzzer

Fuzzes `openssl s_client` with auto-discovered flags, 4 fitness signals, and ASan/UBSan/LeakSan detection.

| Module | Purpose |
|--------|---------|
| `flag_parser.rs` | Auto-discover flags from `openssl s_client -help` (stderr) |
| `flag_overlay.rs` | Load curated flag metadata from TOML |
| `flag_seeds.rs` | Auto-enrich flags with TLS-specific seed values |
| `individual.rs` | `OpenSslIndividual` with flag chromosome |
| `executor.rs` | Spawn openssl s_client, pipe Q to stdin, capture output |
| `fitness.rs` | 4-signal weighted fitness scoring (crash, sanitizer, exit code, timing) |
| `persistence.rs` | SQLite results storage |
| `findings.rs` | Write reproducible .sh scripts |
| `config.rs` | TOML config + CLI override merging |

## curl-fuzzer Details

### Protocols

20 protocols supported:

| Protocol | Port | Protocol | Port |
|----------|------|----------|------|
| http | 8080 | https | 8443 |
| ftp | 2121 | ftps | 9921 |
| smtp | 2525 | smtps | 5587 |
| imap | 1143 | imaps | 9933 |
| pop3 | 1110 | pop3s | 9955 |
| gopher | 7070 | gophers | 7071 |
| dict | 2628 | mqtt | 1883 |
| mqtts | 8883 | tftp | 6969 |
| telnet | 2323 | ws | 8080 |
| wss | 8443 | file | N/A |

Single-protocol mode (`--protocol ftp`) or multi-protocol mode (`--protocols http,ftp,mqtt`) with evolvable protocol selection.

### Fitness Signals (curl-fuzzer)

17 weighted signals:

| # | Signal | Default Weight | What it detects |
|---|--------|---------------|-----------------|
| 1 | Core dump | 150.0 | Process dumped core |
| 2 | Sanitizer | 200.0 | ASan/UBSan/LeakSan/MSan/TSan findings |
| 3 | Crash (signal) | 100.0 | SIGSEGV, SIGBUS, SIGFPE, SIGABRT, etc. |
| 4 | Exit code | 10.0 | Non-zero exit with curl-specific interest |
| 5 | Exit rarity | 5.0 | Rare exit codes across the population |
| 6 | Timing anomaly | 5.0 | Duration >2 stddev above baseline |
| 7 | Stderr keywords | 3.0 | "warning", "error", "overflow", etc. |
| 8 | Stderr size | 2.0 | Unusually large stderr |
| 9 | Stdout size | 2.0 | Unusually large/small response |
| 10 | HTTP anomaly | 2.0 | 5xx status or status 0 |
| 11 | Memory anomaly | 4.0 | Peak RSS >2 stddev above baseline |
| 12 | CPU anomaly | 3.0 | CPU time >2 stddev above baseline |
| 13 | Stderr novelty | 3.0 | First-seen stderr message |
| 14 | Output entropy | 3.0 | High entropy (memory disclosure) or low entropy (truncation) |
| 15 | FD leak | 5.0 | File descriptor count >2 stddev above baseline |
| 16 | Coverage | 10.0 | New code edges discovered (requires instrumented curl) |
| 17 | Verbose anomaly | 4.0 | State machine anomalies from `--verbose` output |

All weights configurable via TOML or CLI. Baselines computed per-protocol using Welford's online algorithm.

### Verbose State Analysis

The fuzzer injects `--verbose` and parses curl's internal state transitions to detect:

- Unexpected reconnects, partial TLS handshakes, missing request/response pairs
- Protocol confusion, connection resets, state machine flooding
- HTTP/2 stream anomalies, unclean connection closures

### curl-fuzzer CLI

```
curl-fuzzer run [OPTIONS]        # Start a fuzzing run
curl-fuzzer replay <id>          # Replay a finding
curl-fuzzer report [--top N]     # Show top findings from SQLite
curl-fuzzer servers [OPTIONS]    # Start test servers standalone
```

### curl-fuzzer Run Options

```
--curl-path <path>           Path to curl binary (default: "curl")
--config <file>              Config TOML file
--population-size <n>        GA population size (default: 50)
--generations <n>            Max generations (default: 15)
--mutation-rate <f>          Mutation rate (default: 0.02)
--crossover-rate <f>         Crossover rate (default: 0.3)
--target-url <url>           Override target URL
--timeout-ms <ms>            Per-curl timeout (default: 3000)
--max-active-flags <n>       Max flags per individual (default: 35)
--protocol <proto>           Single-protocol mode
--protocols <p1,p2,...>      Multi-protocol mode
--no-servers                 Skip starting test servers
--output-dir <dir>           Findings output directory
```

## ls-fuzzer Details

### Fitness Signals (ls-fuzzer)

| Signal | Default Weight | What it detects |
|--------|---------------|-----------------|
| Crash (signal) | 100.0 | SIGSEGV, SIGBUS, etc. with severity |
| Exit code | 5.0 | Exit 2 (serious), unexpected codes |
| Stderr critical | 9.0 | "segfault", "overflow", "corrupt", "assertion" |
| Stderr error | 3.0 | "invalid", "unrecognized" |
| Timing | 5.0 | Execution >1 second |
| Output size | 2.0 | Extremely large output (>100KB) |
| Timeout | 10.0 | Hung process |

### ls-fuzzer CLI

```
ls-fuzzer run [OPTIONS]          # Start a fuzzing run
ls-fuzzer report [--top N]       # Show top findings from SQLite
```

### ls-fuzzer Run Options

```
--ls-path <path>             Path to ls binary (default: "ls")
--target <dir>               Target directory (default: auto-generated fixtures)
--population-size <n>        GA population size (default: 50)
--generations <n>            Max generations (default: 20)
--mutation-rate <f>          Mutation rate (default: 0.05)
--crossover-rate <f>         Crossover rate (default: 0.4)
--max-active-flags <n>       Max active flags per individual (default: 15)
--timeout-ms <ms>            Per-execution timeout (default: 5000)
--seed <n>                   Random seed for reproducibility
--database-path <path>       SQLite database path (default: "ls-fuzzer.db")
--findings-dir <dir>         Findings output directory (default: "ls-findings")
--fitness-threshold <f>      Minimum fitness to save as finding (default: 5.0)
```

### Test Fixtures

When no `--target` is specified, ls-fuzzer auto-creates a rich test directory with:

- Regular files, hidden files, empty files
- Large binary files (1MB)
- Files with special characters (spaces, tabs, newlines)
- Deep nested directories
- Symlinks (normal, broken, circular)
- 200+ files in a single directory
- Files with various extensions

## openssl-fuzzer Details

### Fitness Signals (openssl-fuzzer)

6 weighted signals:

| # | Signal | Default Weight | What it detects |
|---|--------|---------------|-----------------|
| 1 | Crash (signal) | 100.0 | SIGSEGV, SIGBUS, SIGFPE, SIGABRT, SIGILL |
| 2 | Sanitizer | 200.0 | ASan/UBSan/LeakSan/MSan/TSan findings |
| 3 | Exit code | 10.0 | Non-zero exit (exit 1 = low interest, others = high) |
| 4 | Timing anomaly | 5.0 | Handshake duration >2 seconds |
| 5 | TLS anomaly | 15.0 | Incomplete handshakes, weak ciphers, protocol downgrades, renegotiation, interesting alerts |
| 6 | Memory anomaly | 8.0 | Peak RSS >2 stddev above baseline (via wait4/rusage) |

### TLS Handshake State Analysis

The fuzzer parses `s_client` output to detect TLS state machine anomalies:

- Incomplete handshakes (connected but no handshake completion)
- Weak/NULL/EXPORT/ANON cipher selection
- Protocol downgrades (SSLv2, SSLv3, TLSv1.0)
- Renegotiation events
- Interesting TLS alerts (decode_error, internal_error, bad_record_mac, etc.)
- Certificate verification anomalies (revoked, chain too long, invalid purpose)
- SSL internal errors without corresponding alerts

### openssl-fuzzer CLI

```
openssl-fuzzer run [OPTIONS]     # Start a fuzzing run
openssl-fuzzer report [--top N]  # Show top findings from SQLite
```

### openssl-fuzzer Run Options

```
--openssl-path <path>        Path to openssl binary
--connect <host:port>        Target to connect to (default: localhost:8443)
--config <file>              Config TOML file
--population-size <n>        GA population size (default: 50)
--generations <n>            Max generations (default: 100)
--mutation-rate <f>          Mutation rate (default: 0.05)
--crossover-rate <f>         Crossover rate (default: 0.8)
--max-active-flags <n>       Max flags per individual (default: 20)
--timeout-ms <ms>            Per-execution timeout (default: 5000)
--seed <n>                   Random seed for reproducibility
--database-path <path>       SQLite database path (default: "openssl-fuzzer.db")
--findings-dir <dir>         Findings output directory (default: "openssl-findings")
--fitness-threshold <f>      Minimum fitness to save as finding (default: 5.0)
```

## Configuration (curl-fuzzer)

`config/curl-default.toml` controls curl-fuzzer parameters:

```toml
[ga]
population_size = 50
max_generations = 15
mutation_rate = 0.02
crossover_rate = 0.3
elitism_percent = 0.1

[curl]
curl_path = "curl"
timeout_ms = 3000
target_url = "http://localhost:8080"

[fitness]
weight_crash = 100.0
weight_sanitizer = 200.0
# ... all 17 weights configurable

[protocols]
enabled = ["http", "https", "ftp", "smtp", "imap"]
blocking_timeout_s = 5

[output]
database_path = "curl-fuzzer.db"
findings_dir = "curl-findings"
fitness_threshold = 5.0
```

## Test Servers (curl-fuzzer)

Python-based, managed automatically. Each server supports normal and malformed response modes. TLS variants use `--tls` flag with a shared self-signed certificate.

```bash
pip install -r test-servers/requirements.txt
cargo run -p curl-fuzzer -- servers
cargo run -p curl-fuzzer -- servers --protocols http,ftp,mqtt
```

## Running Tests

```bash
make test                    # All tests
cargo test -p curl-fuzzer    # curl-fuzzer only (97 tests)
cargo test -p ls-fuzzer      # ls-fuzzer only (26 tests)
cargo test -p openssl-fuzzer # openssl-fuzzer only (55 tests)
cargo test -p ga-engine      # ga-engine only
```

## Suggested Run Configurations

### curl-fuzzer

| Scenario | Population | Generations | Time |
|----------|-----------|-------------|------|
| Quick smoke test | 10 | 5 | ~1 min |
| Development | 50 | 100 | ~1.5 hours |
| Overnight | 250 | 500 | ~33 hours |
| Week-long | 250 | 1000 | ~66 hours |

### ls-fuzzer

| Scenario | Population | Generations | Time |
|----------|-----------|-------------|------|
| Quick smoke test | 10 | 5 | ~10 sec |
| Development | 50 | 100 | ~5 min |
| Thorough | 100 | 500 | ~30 min |

ls executions are much faster than curl (~10ms vs ~1s), so runs complete quickly.

### openssl-fuzzer

| Scenario | Population | Generations |
|----------|-----------|-------------|
| Quick smoke test | 10 | 5 |
| Development | 50 | 100 |
| Overnight | 250 | 500 |

## Adding a New Fuzzer Target

1. Create a new crate in the workspace (e.g., `my-fuzzer/`)
2. Add it to `Cargo.toml` workspace members
3. Depend on `ga-engine` for the GA traits and engine
4. Implement `Individual`, `FitnessEvaluator`, `MutationOperator`, `CrossoverOperator`
5. Wire up a `main.rs` with clap CLI
6. Run with `cargo run -p my-fuzzer -- run`

Zero changes needed to `ga-engine` or other fuzzers.

## Docs
