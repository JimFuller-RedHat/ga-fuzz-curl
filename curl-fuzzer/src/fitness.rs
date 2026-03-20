use crate::executor::{execute_curl, ExecutionResult};
use crate::individual::CurlIndividual;
use crate::protocol::ProtocolRegistry;
use ga_engine::fitness::FitnessScore;
use ga_engine::traits::FitnessEvaluator;

pub struct CurlFitnessScorer {
    pub crash_weight: f64,
    pub exit_code_weight: f64,
    pub timing_weight: f64,
    pub stderr_weight: f64,
    pub http_anomaly_weight: f64,
    pub memory_weight: f64,
    pub cpu_weight: f64,
    pub core_dump_weight: f64,
    pub stderr_size_weight: f64,
    pub stdout_size_weight: f64,
    pub exit_rarity_weight: f64,
    pub sanitizer_weight: f64,
    pub stderr_novelty_weight: f64,
    pub entropy_weight: f64,
    pub fd_leak_weight: f64,
    pub coverage_weight: f64,
    pub verbose_anomaly_weight: f64,
    pub timing_breakdown_weight: f64,
    pub size_ratio_weight: f64,
    pub redirect_weight: f64,
    pub nondeterminism_weight: f64,
}

impl Default for CurlFitnessScorer {
    fn default() -> Self {
        Self {
            crash_weight: 100.0,
            exit_code_weight: 10.0,
            timing_weight: 5.0,
            stderr_weight: 3.0,
            http_anomaly_weight: 2.0,
            memory_weight: 4.0,
            cpu_weight: 3.0,
            core_dump_weight: 150.0,
            stderr_size_weight: 2.0,
            stdout_size_weight: 2.0,
            exit_rarity_weight: 5.0,
            sanitizer_weight: 200.0,
            stderr_novelty_weight: 3.0,
            entropy_weight: 3.0,
            fd_leak_weight: 5.0,
            coverage_weight: 10.0,
            verbose_anomaly_weight: 4.0,
            timing_breakdown_weight: 6.0,
            size_ratio_weight: 4.0,
            redirect_weight: 5.0,
            nondeterminism_weight: 20.0,
        }
    }
}

/// Context passed to the scorer with additional information about the execution
pub struct ScoringContext {
    pub stderr_novel: bool,
    pub new_coverage_edges: Option<u64>,  // reserved for coverage signal later
    pub verbose_anomaly_score: f64,
    #[allow(dead_code)]
    pub verbose_labels: Vec<&'static str>,
    pub nondeterminism_score: f64,
}

impl Default for ScoringContext {
    fn default() -> Self {
        Self {
            stderr_novel: false,
            new_coverage_edges: None,
            verbose_anomaly_score: 0.0,
            verbose_labels: Vec::new(),
            nondeterminism_score: 0.0,
        }
    }
}

/// Compute Shannon entropy of byte data
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Scan stderr for AddressSanitizer / UBSan / LeakSanitizer patterns.
/// Returns a severity score (0.0 if none found, up to 1.0 for the worst).
fn sanitizer_severity(stderr: &str) -> (f64, &'static str) {
    // Check from most severe to least; return first match
    let checks: &[(&[&str], f64, &str)] = &[
        // Memory corruption - highest severity
        (&["heap-buffer-overflow"], 1.0, "heap-buffer-overflow"),
        (&["stack-buffer-overflow"], 1.0, "stack-buffer-overflow"),
        (&["global-buffer-overflow"], 1.0, "global-buffer-overflow"),
        (&["use-after-free"], 1.0, "use-after-free"),
        (&["heap-use-after-free"], 1.0, "heap-use-after-free"),
        (&["stack-use-after-free"], 1.0, "stack-use-after-free"),
        (&["double-free"], 1.0, "double-free"),
        (&["use-after-poison"], 0.9, "use-after-poison"),
        (&["container-overflow"], 0.9, "container-overflow"),
        (&["alloc-dealloc-mismatch"], 0.8, "alloc-dealloc-mismatch"),
        (&["stack-overflow"], 0.8, "stack-overflow"),
        // UBSan issues
        (&["undefined behavior"], 0.7, "undefined-behavior"),
        (&["UndefinedBehaviorSanitizer"], 0.7, "undefined-behavior"),
        (&["signed integer overflow"], 0.6, "integer-overflow"),
        (&["unsigned integer overflow"], 0.5, "integer-overflow"),
        (&["division by zero"], 0.7, "division-by-zero"),
        (&["shift exponent"], 0.5, "shift-exponent"),
        (&["null pointer"], 0.7, "null-pointer"),
        (&["misaligned address", "alignment"], 0.5, "alignment"),
        (&["object-size"], 0.5, "object-size"),
        // Memory leaks (less severe but still interesting)
        (&["LeakSanitizer"], 0.4, "memory-leak"),
        (&["detected memory leaks"], 0.4, "memory-leak"),
        // Generic sanitizer catch-all
        (&["AddressSanitizer"], 0.6, "asan-generic"),
        (&["MemorySanitizer"], 0.6, "msan-generic"),
        (&["ThreadSanitizer"], 0.5, "tsan-generic"),
    ];

    for (patterns, severity, label) in checks {
        for pattern in *patterns {
            if stderr.contains(pattern) {
                return (*severity, label);
            }
        }
    }

    (0.0, "")
}

/// Signal severity: SIGSEGV, SIGBUS, SIGFPE are more interesting than SIGPIPE, SIGTERM
fn signal_severity(signal: i32) -> f64 {
    match signal {
        11 => 1.0,  // SIGSEGV - segfault, the holy grail
        7  => 1.0,  // SIGBUS - bus error, memory alignment
        8  => 0.9,  // SIGFPE - floating point exception
        6  => 0.8,  // SIGABRT - abort (often from assert or sanitizer)
        4  => 0.7,  // SIGILL - illegal instruction
        _  => 0.3,  // SIGPIPE, SIGTERM, etc - less interesting
    }
}

/// Scale a z-score into a fitness contribution using logarithmic diminishing returns.
/// This replaces the old `(z - 2.0).min(10.0)` hard cap that created fitness plateaus.
/// z=3 → ~1.0, z=5 → ~2.1, z=10 → ~3.2, z=50 → ~4.6, z=100 → ~5.3
fn zscore_contribution(z: f64) -> f64 {
    if z <= 2.0 {
        return 0.0;
    }
    // ln(z - 1) gives good diminishing returns: always increasing, never capped
    (z - 1.0).ln()
}

/// Curl exit code interest: some exit codes indicate more interesting behavior
fn curl_exit_code_interest(exit_code: i32) -> f64 {
    match exit_code {
        27 => 2.0,  // Out of memory
        56 => 1.5,  // Failure in receiving network data
        52 => 1.5,  // Server returned nothing (empty reply)
        18 => 1.5,  // Partial file transfer
        63 => 1.5,  // Transfer size exceeded
        55 => 1.3,  // Sending network data failed
        23 => 1.3,  // Write error
        26 => 1.3,  // Read error
        92 => 1.3,  // Stream error in HTTP/2
        61 => 1.2,  // Bad transfer encoding
        16 => 1.2,  // HTTP/2 error
        95 => 1.2,  // SSL pinning failure
        42 => 1.1,  // Aborted by callback
        28 => 0.5,  // Timeout - expected with short timeouts
        6  => 0.3,  // Couldn't resolve host - boring
        7  => 0.3,  // Couldn't connect - boring
        _  => 1.0,  // Everything else: neutral
    }
}

impl CurlFitnessScorer {
    pub fn score(
        &self,
        result: &ExecutionResult,
        baselines: &Baselines,
        ctx: &ScoringContext,
    ) -> FitnessScore {
        let mut components = Vec::new();

        // 1. Core dump detection (highest priority)
        if result.core_dumped {
            components.push(("core_dump", self.core_dump_weight));
        }

        // 2. Sanitizer detection (ASAN, UBSan, LeakSan, MSan, TSan)
        let (san_severity, san_label) = sanitizer_severity(&result.stderr);
        if san_severity > 0.0 {
            components.push((san_label, self.sanitizer_weight * san_severity));
        }

        // 3. Signal with severity differentiation
        if let Some(signal) = result.signal {
            let severity = signal_severity(signal);
            components.push(("crash", self.crash_weight * severity));
        }

        // 3. Non-zero exit code with curl-specific interest multiplier
        if result.signal.is_none() && result.exit_code != 0 {
            let interest = curl_exit_code_interest(result.exit_code);
            components.push(("exit_code", self.exit_code_weight * interest));
        }

        // 4. Exit code rarity bonus
        if result.exit_code != 0 && baselines.total_runs > 10 {
            if let Some(&count) = baselines.exit_code_counts.get(&result.exit_code) {
                let frequency = count as f64 / baselines.total_runs as f64;
                // Rarer exit codes get higher scores. <1% = full weight, <5% = half, etc.
                if frequency < 0.05 {
                    let rarity_score = self.exit_rarity_weight * (1.0 - frequency * 20.0);
                    components.push(("exit_rarity", rarity_score));
                }
            }
        }

        // 5. Timing anomaly (>2 stddev above mean)
        if baselines.stddev_duration > 0.0 {
            let z_score = (result.duration_ms as f64 - baselines.mean_duration) / baselines.stddev_duration;
            if z_score > 2.0 {
                let timing_score = self.timing_weight * zscore_contribution(z_score);
                components.push(("timing", timing_score));
            }
        }

        // 6. Stderr keyword detection
        let stderr_lower = result.stderr.to_lowercase();
        if stderr_lower.contains("warning")
            || stderr_lower.contains("error")
            || stderr_lower.contains("segfault")
            || stderr_lower.contains("abort")
            || stderr_lower.contains("overflow")
        {
            components.push(("stderr", self.stderr_weight));
        }

        // 7. Stderr size anomaly (unusually large stderr)
        if baselines.stddev_stderr_len > 0.0 {
            let z_score = (result.stderr.len() as f64 - baselines.mean_stderr_len) / baselines.stddev_stderr_len;
            if z_score > 2.0 {
                let score = self.stderr_size_weight * zscore_contribution(z_score);
                components.push(("stderr_size", score));
            }
        }

        // 8. Stdout size anomaly (unusually large or small response)
        if baselines.stddev_stdout_len > 0.0 {
            let z_score = ((result.stdout.len() as f64 - baselines.mean_stdout_len) / baselines.stddev_stdout_len).abs();
            if z_score > 2.0 {
                let score = self.stdout_size_weight * zscore_contribution(z_score);
                components.push(("stdout_size", score));
            }
        }

        // 9. HTTP status anomalies
        if let Some(status) = result.http_status {
            if status >= 500 || status == 0 {
                components.push(("http_anomaly", self.http_anomaly_weight));
            }
        }

        // 10. Memory anomaly: high RSS compared to baseline
        if let (Some(rss), true) = (result.peak_rss_kb, baselines.stddev_rss > 0.0) {
            let z_score = (rss as f64 - baselines.mean_rss) / baselines.stddev_rss;
            if z_score > 2.0 {
                let mem_score = self.memory_weight * zscore_contribution(z_score);
                components.push(("memory", mem_score));
            }
        }

        // 11. CPU anomaly: high user+sys CPU time compared to baseline
        if let (Some(user), Some(sys)) = (result.cpu_user_ms, result.cpu_sys_ms) {
            let total_cpu = (user + sys) as f64;
            if baselines.stddev_cpu > 0.0 {
                let z_score = (total_cpu - baselines.mean_cpu) / baselines.stddev_cpu;
                if z_score > 2.0 {
                    let cpu_score = self.cpu_weight * zscore_contribution(z_score);
                    components.push(("cpu", cpu_score));
                }
            }
        }

        // 12. Stderr novelty bonus
        if ctx.stderr_novel {
            components.push(("stderr_novelty", self.stderr_novelty_weight));
        }

        // 13. Output entropy anomaly
        if !result.stdout.is_empty() && result.stdout.len() > 10 {
            let entropy = shannon_entropy(result.stdout.as_bytes());
            // High entropy suggests random/binary data (possible memory disclosure)
            if entropy > 6.0 {
                let score = self.entropy_weight * (entropy - 6.0);
                components.push(("entropy_high", score));
            }
            // Very low entropy on non-trivial output suggests truncation/corruption
            else if entropy < 1.0 {
                let score = self.entropy_weight * (1.0 - entropy);
                components.push(("entropy_low", score));
            }
        }

        // 14. FD leak detection
        if let Some(fd_count) = result.max_fd_count {
            if baselines.stddev_fd_count > 0.0 {
                let z_score = (fd_count as f64 - baselines.mean_fd_count) / baselines.stddev_fd_count;
                if z_score > 2.0 {
                    let fd_score = self.fd_leak_weight * zscore_contribution(z_score);
                    components.push(("fd_leak", fd_score));
                }
            }
        }

        // 15. Coverage-guided feedback: reward new edge discovery
        if let Some(new_edges) = ctx.new_coverage_edges {
            if new_edges > 0 {
                // Log scale: discovering 1 new edge is good, 100 is great
                let edge_score = self.coverage_weight * (1.0 + (new_edges as f64).ln());
                components.push(("coverage", edge_score));
            }
        }

        // 16. Verbose state machine anomaly
        if ctx.verbose_anomaly_score > 0.0 {
            let verbose_score = self.verbose_anomaly_weight * ctx.verbose_anomaly_score;
            components.push(("verbose_anomaly", verbose_score));
        }

        // 17. Transfer timing breakdown anomalies
        //     Detect phase-level bottlenecks from curl's timing data
        if let (Some(t_connect), Some(t_start), Some(t_total)) = (
            result.write_out.time_connect,
            result.write_out.time_starttransfer,
            result.write_out.time_total,
        ) {
            if t_total > 0.001 {
                let mut timing_score = 0.0;

                // Server processing delay: time_starttransfer close to time_total
                // means server took most of the time (potential complexity attack)
                let server_ratio = if t_total > 0.0 { (t_start - t_connect) / t_total } else { 0.0 };
                if server_ratio > 0.8 {
                    timing_score += (server_ratio - 0.8) * 5.0;
                }

                // TLS handshake stall: appconnect >> connect
                if let Some(t_app) = result.write_out.time_appconnect {
                    if t_app > 0.0 && t_connect > 0.0 {
                        let tls_ratio = (t_app - t_connect) / t_total;
                        if tls_ratio > 0.5 {
                            timing_score += (tls_ratio - 0.5) * 3.0;
                        }
                    }
                }

                // Multiple connections without redirects
                if let (Some(nc), Some(nr)) = (result.write_out.num_connects, result.write_out.num_redirects) {
                    if nc > 1 && nr == 0 {
                        timing_score += (nc - 1) as f64 * 0.5;
                    }
                }

                if timing_score > 0.0 {
                    components.push(("timing_breakdown", self.timing_breakdown_weight * timing_score));
                }
            }
        }

        // 18. Response/request size ratio anomaly
        if let (Some(dl), Some(req)) = (result.write_out.size_download, result.write_out.size_request) {
            if req > 0 {
                let ratio = dl as f64 / req as f64;
                let mut size_score = 0.0;

                // Amplification: small request, huge response (>100x)
                if ratio > 100.0 {
                    size_score += (ratio / 100.0).ln() + 1.0;
                }
                // Suppression: large request, zero response
                if dl == 0 && req > 100 {
                    size_score += 0.5;
                }

                if size_score > 0.0 {
                    components.push(("size_ratio", self.size_ratio_weight * size_score));
                }
            }
        }

        // 19. Redirect chain analysis
        if let Some(nr) = result.write_out.num_redirects {
            if nr > 0 {
                let mut redirect_score = 0.0;

                // Deep redirect chains (>3 hops)
                if nr > 3 {
                    redirect_score += (nr - 3) as f64 * 0.3;
                }

                // Protocol-switching redirect (scheme changed from original)
                if let Some(ref scheme) = result.write_out.scheme {
                    if let Some(ref redir_url) = result.write_out.redirect_url {
                        let redir_lower = redir_url.to_lowercase();
                        let scheme_lower = scheme.to_lowercase();
                        if !redir_lower.starts_with(&format!("{}://", scheme_lower)) {
                            redirect_score += 0.8;
                        }
                    }
                }

                // Redirect with timeout suggests a redirect loop
                if result.timed_out && nr > 2 {
                    redirect_score += 1.0;
                }

                if redirect_score > 0.0 {
                    components.push(("redirect", self.redirect_weight * redirect_score));
                }
            }
        }

        // 20. Non-determinism bonus (computed by evaluator, passed via context)
        if ctx.nondeterminism_score > 0.0 {
            components.push(("nondeterminism", self.nondeterminism_weight * ctx.nondeterminism_score));
        }

        FitnessScore::from_weighted(&components)
    }
}

/// Running baselines for anomaly detection. Updated as executions accumulate.
#[derive(Debug, Clone)]
pub struct Baselines {
    pub mean_duration: f64,
    pub stddev_duration: f64,
    pub mean_rss: f64,
    pub stddev_rss: f64,
    pub mean_cpu: f64,
    pub stddev_cpu: f64,
    pub mean_stderr_len: f64,
    pub stddev_stderr_len: f64,
    pub mean_stdout_len: f64,
    pub stddev_stdout_len: f64,
    pub mean_fd_count: f64,
    pub stddev_fd_count: f64,
    pub exit_code_counts: std::collections::HashMap<i32, usize>,
    pub total_runs: usize,
}

impl Default for Baselines {
    fn default() -> Self {
        Self {
            mean_duration: 100.0,
            stddev_duration: 20.0,
            mean_rss: 0.0,
            stddev_rss: 0.0,
            mean_cpu: 0.0,
            stddev_cpu: 0.0,
            mean_stderr_len: 0.0,
            stddev_stderr_len: 0.0,
            mean_stdout_len: 0.0,
            stddev_stdout_len: 0.0,
            mean_fd_count: 0.0,
            stddev_fd_count: 0.0,
            exit_code_counts: std::collections::HashMap::new(),
            total_runs: 0,
        }
    }
}

/// Welford's online algorithm for computing running mean and stddev.
pub struct RunningStats {
    count: u64,
    mean: f64,
    m2: f64,
}

impl RunningStats {
    pub fn new() -> Self {
        Self { count: 0, mean: 0.0, m2: 0.0 }
    }

    pub fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }

    pub fn stddev(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            (self.m2 / (self.count - 1) as f64).sqrt()
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ProtocolExpectations {
    pub normal_exit_codes: Vec<i32>,
    pub interesting_exit_codes: Vec<i32>,
    pub timeout_baseline_ms: u64,
}

impl Default for ProtocolExpectations {
    fn default() -> Self {
        Self {
            normal_exit_codes: vec![0],
            interesting_exit_codes: vec![28],
            timeout_baseline_ms: 5000,
        }
    }
}

pub struct ProtocolRunningStats {
    pub duration: RunningStats,
    pub rss: RunningStats,
    pub cpu: RunningStats,
    pub stderr_len: RunningStats,
    pub stdout_len: RunningStats,
    pub fd_count: RunningStats,
    pub exit_code_counts: std::collections::HashMap<i32, usize>,
    pub total_runs: usize,
}

impl ProtocolRunningStats {
    pub fn new() -> Self {
        Self {
            duration: RunningStats::new(),
            rss: RunningStats::new(),
            cpu: RunningStats::new(),
            stderr_len: RunningStats::new(),
            stdout_len: RunningStats::new(),
            fd_count: RunningStats::new(),
            exit_code_counts: std::collections::HashMap::new(),
            total_runs: 0,
        }
    }
}

pub struct PerProtocolBaselines {
    stats: std::collections::HashMap<String, ProtocolRunningStats>,
}

impl PerProtocolBaselines {
    pub fn new() -> Self {
        Self {
            stats: std::collections::HashMap::new(),
        }
    }

    pub fn update(&mut self, protocol: &str, duration: f64, rss: Option<f64>, cpu: Option<f64>, stderr_len: f64, stdout_len: f64, fd_count: Option<f64>) {
        let entry = self.stats.entry(protocol.to_string()).or_insert_with(ProtocolRunningStats::new);
        entry.duration.update(duration);
        if let Some(r) = rss {
            entry.rss.update(r);
        }
        if let Some(c) = cpu {
            entry.cpu.update(c);
        }
        entry.stderr_len.update(stderr_len);
        entry.stdout_len.update(stdout_len);
        if let Some(fd) = fd_count {
            entry.fd_count.update(fd);
        }
        entry.total_runs += 1;
    }

    pub fn baselines_for(&self, protocol: &str) -> Baselines {
        match self.stats.get(protocol) {
            Some(s) => Baselines {
                mean_duration: s.duration.mean(),
                stddev_duration: s.duration.stddev(),
                mean_rss: s.rss.mean(),
                stddev_rss: s.rss.stddev(),
                mean_cpu: s.cpu.mean(),
                stddev_cpu: s.cpu.stddev(),
                mean_stderr_len: s.stderr_len.mean(),
                stddev_stderr_len: s.stderr_len.stddev(),
                mean_stdout_len: s.stdout_len.mean(),
                stddev_stdout_len: s.stdout_len.stddev(),
                mean_fd_count: s.fd_count.mean(),
                stddev_fd_count: s.fd_count.stddev(),
                exit_code_counts: s.exit_code_counts.clone(),
                total_runs: s.total_runs,
            },
            None => Baselines::default(),
        }
    }
}

#[allow(dead_code)]
pub fn diversity_bonus(
    protocol: &str,
    protocol_counts: &std::collections::HashMap<String, usize>,
    weight: f64,
) -> f64 {
    let count = protocol_counts.get(protocol).copied().unwrap_or(1) as f64;
    weight / count
}

pub struct CurlFitnessEvaluator {
    pub curl_path: String,
    pub target_url: String,
    pub timeout_ms: u64,
    pub blocking_timeout_s: u64,
    pub cert_path: Option<String>,
    pub scorer: CurlFitnessScorer,
    pub registry: ProtocolRegistry,
    pub port_overrides: std::collections::HashMap<String, u16>,
    pub state_dir: Option<String>,
    // per-protocol stats
    protocol_baselines: std::sync::Mutex<PerProtocolBaselines>,
    // global stats (kept for backwards compat)
    duration_stats: std::sync::Mutex<RunningStats>,
    rss_stats: std::sync::Mutex<RunningStats>,
    cpu_stats: std::sync::Mutex<RunningStats>,
    stderr_len_stats: std::sync::Mutex<RunningStats>,
    stdout_len_stats: std::sync::Mutex<RunningStats>,
    exit_code_counts: std::sync::Mutex<std::collections::HashMap<i32, usize>>,
    total_runs: std::sync::atomic::AtomicUsize,
    seen_stderr_hashes: std::sync::Mutex<std::collections::HashSet<u64>>,
    pub coverage_tracker: crate::coverage::CoverageTracker,
    pub coverage_enabled: bool,
    pub gcov_source_root: String,
    pub gcov_strip_count: u32,
}

impl CurlFitnessEvaluator {
    pub fn new(curl_path: String, target_url: String, timeout_ms: u64, scorer: CurlFitnessScorer) -> Self {
        Self {
            curl_path,
            target_url,
            timeout_ms,
            blocking_timeout_s: 5,
            cert_path: None,
            scorer,
            registry: ProtocolRegistry::default(),
            port_overrides: std::collections::HashMap::new(),
            state_dir: None,
            protocol_baselines: std::sync::Mutex::new(PerProtocolBaselines::new()),
            duration_stats: std::sync::Mutex::new(RunningStats::new()),
            rss_stats: std::sync::Mutex::new(RunningStats::new()),
            cpu_stats: std::sync::Mutex::new(RunningStats::new()),
            stderr_len_stats: std::sync::Mutex::new(RunningStats::new()),
            stdout_len_stats: std::sync::Mutex::new(RunningStats::new()),
            exit_code_counts: std::sync::Mutex::new(std::collections::HashMap::new()),
            total_runs: std::sync::atomic::AtomicUsize::new(0),
            seen_stderr_hashes: std::sync::Mutex::new(std::collections::HashSet::new()),
            coverage_tracker: crate::coverage::CoverageTracker::new(),
            coverage_enabled: true,
            gcov_source_root: "/home/jfuller/src/curl".to_string(),
            gcov_strip_count: 5,
        }
    }

    #[allow(dead_code)]
    fn baselines(&self) -> Baselines {
        let ds = self.duration_stats.lock().unwrap();
        let rs = self.rss_stats.lock().unwrap();
        let cs = self.cpu_stats.lock().unwrap();
        let ss = self.stderr_len_stats.lock().unwrap();
        let os = self.stdout_len_stats.lock().unwrap();
        let ec = self.exit_code_counts.lock().unwrap();
        Baselines {
            mean_duration: ds.mean(),
            stddev_duration: ds.stddev(),
            mean_rss: rs.mean(),
            stddev_rss: rs.stddev(),
            mean_cpu: cs.mean(),
            stddev_cpu: cs.stddev(),
            mean_stderr_len: ss.mean(),
            stddev_stderr_len: ss.stddev(),
            mean_stdout_len: os.mean(),
            stddev_stdout_len: os.stddev(),
            mean_fd_count: 0.0,
            stddev_fd_count: 0.0,
            exit_code_counts: ec.clone(),
            total_runs: self.total_runs.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

impl FitnessEvaluator<CurlIndividual> for CurlFitnessEvaluator {
    fn evaluate(&self, individual: &CurlIndividual) -> FitnessScore {
        let protocol_name = individual.protocol_name();

        // Construct URL: use target_url if non-empty override, else from registry
        let target_url = if !self.target_url.is_empty() {
            self.target_url.clone()
        } else {
            let proto_def = self.registry.get(protocol_name);
            match proto_def {
                Some(p) => {
                    let port = self.port_overrides.get(protocol_name).copied()
                        .unwrap_or(p.default_port);
                    self.registry.url_for(protocol_name, port)
                }
                None => self.target_url.clone(),
            }
        };

        // Determine TLS and blocking status from registry
        let is_tls = self.registry.is_tls_protocol(protocol_name);
        let is_blocking = self.registry.get(protocol_name)
            .map(|p| p.blocking_protocol)
            .unwrap_or(false);
        let cert_path = if is_tls { self.cert_path.as_deref() } else { None };

        let mut args = individual.to_curl_args();
        args.push(target_url);

        let coverage_cfg = if self.coverage_enabled {
            Some(crate::executor::CoverageConfig {
                source_root: self.gcov_source_root.clone(),
                strip_count: self.gcov_strip_count,
            })
        } else {
            None
        };

        let result = match execute_curl(
            &self.curl_path, &args, self.timeout_ms,
            is_tls, is_blocking, self.blocking_timeout_s, cert_path, coverage_cfg.as_ref(),
        ) {
            Ok(r) => r,
            Err(_) => {
                return FitnessScore::new(0.0);
            }
        };

        // Timed-out individuals get zero fitness — the GA will naturally
        // select against them, effectively removing them from the gene pool
        if result.timed_out {
            return FitnessScore::new(0.0);
        }

        // Record coverage edges and get new edge count
        let new_coverage_edges = if self.coverage_enabled {
            let new_count = self.coverage_tracker.record_edges(&result.coverage_edges);
            if new_count > 0 { Some(new_count) } else { None }
        } else {
            None
        };

        // Update global running statistics
        self.duration_stats.lock().unwrap().update(result.duration_ms as f64);
        if let Some(rss) = result.peak_rss_kb {
            self.rss_stats.lock().unwrap().update(rss as f64);
        }
        if let (Some(user), Some(sys)) = (result.cpu_user_ms, result.cpu_sys_ms) {
            self.cpu_stats.lock().unwrap().update((user + sys) as f64);
        }
        self.stderr_len_stats.lock().unwrap().update(result.stderr.len() as f64);
        self.stdout_len_stats.lock().unwrap().update(result.stdout.len() as f64);
        *self.exit_code_counts.lock().unwrap().entry(result.exit_code).or_insert(0) += 1;
        self.total_runs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Update per-protocol baselines
        let rss_f64 = result.peak_rss_kb.map(|r| r as f64);
        let cpu_f64 = match (result.cpu_user_ms, result.cpu_sys_ms) {
            (Some(u), Some(s)) => Some((u + s) as f64),
            _ => None,
        };
        let fd_f64 = result.max_fd_count.map(|f| f as f64);
        self.protocol_baselines.lock().unwrap().update(
            protocol_name,
            result.duration_ms as f64,
            rss_f64,
            cpu_f64,
            result.stderr.len() as f64,
            result.stdout.len() as f64,
            fd_f64,
        );

        // Check stderr novelty
        let stderr_novel = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            result.stderr.hash(&mut hasher);
            let hash = hasher.finish();
            let mut seen = self.seen_stderr_hashes.lock().unwrap();
            seen.insert(hash) // returns true if newly inserted
        };

        // Analyze verbose state transitions
        let verbose = crate::verbose_state::analyze_verbose(&result.stderr);

        // Non-determinism detection: re-run interesting individuals to detect instability
        let nondeterminism_score = if result.exit_code != 0 || result.signal.is_some() {
            // Re-run the same command once more
            let result2 = execute_curl(
                &self.curl_path, &args, self.timeout_ms,
                is_tls, is_blocking, self.blocking_timeout_s, cert_path, None,
            );
            match result2 {
                Ok(r2) if !r2.timed_out => {
                    let mut diff_score = 0.0;
                    // Different exit code = strong signal
                    if r2.exit_code != result.exit_code {
                        diff_score += 0.5;
                    }
                    // Different signal
                    if r2.signal != result.signal {
                        diff_score += 0.5;
                    }
                    // Different HTTP status
                    if r2.http_status != result.http_status {
                        diff_score += 0.3;
                    }
                    // Significantly different stdout size (>50% difference)
                    let s1 = result.stdout.len() as f64;
                    let s2 = r2.stdout.len() as f64;
                    if s1 > 10.0 || s2 > 10.0 {
                        let max_s = s1.max(s2);
                        if max_s > 0.0 && (s1 - s2).abs() / max_s > 0.5 {
                            diff_score += 0.2;
                        }
                    }
                    diff_score
                }
                _ => 0.0,
            }
        } else {
            0.0
        };

        let ctx = ScoringContext {
            stderr_novel,
            new_coverage_edges,
            verbose_anomaly_score: verbose.anomaly_score,
            verbose_labels: verbose.labels,
            nondeterminism_score,
        };

        // Use per-protocol baselines for scoring
        let baselines = self.protocol_baselines.lock().unwrap().baselines_for(protocol_name);
        let mut score = self.scorer.score(&result, &baselines, &ctx);

        // Read server malformation state file if available
        if let Some(ref state_dir) = self.state_dir {
            let state_file = std::path::Path::new(state_dir).join(format!("{}.state", protocol_name));
            if let Ok(content) = std::fs::read_to_string(&state_file) {
                let malformation = content.trim().to_string();
                if !malformation.is_empty() {
                    score.metadata.insert("server_malformation".to_string(), malformation);
                }
            }
        }

        score
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::CurlWriteOut;

    #[test]
    fn test_normal_execution_low_fitness() {
        let scorer = CurlFitnessScorer::default();

        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: "OK".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, // Use mean duration to avoid timing anomaly
            http_status: Some(200),
            peak_rss_kb: None,
            cpu_user_ms: None,
            cpu_sys_ms: None,
            core_dumped: false,
            timed_out: false,
            max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };

        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());

        // Normal execution should have low fitness
        assert!(score.total < 1.0);
    }

    #[test]
    fn test_crash_high_fitness() {
        let scorer = CurlFitnessScorer::default();

        let result = ExecutionResult {
            exit_code: -1,
            signal: Some(11),
            stdout: "".to_string(),
            stderr: "Segmentation fault".to_string(),
            duration_ms: 50,
            http_status: None,
            peak_rss_kb: None,
            cpu_user_ms: None,
            cpu_sys_ms: None,
            core_dumped: false,
            timed_out: false,
            max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };

        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());

        // Crash should have high fitness (>= 100)
        assert!(score.total >= 100.0);
        assert!(score.components.contains_key("crash"));
    }

    #[test]
    fn test_non_zero_exit_fitness() {
        let scorer = CurlFitnessScorer::default();

        let result = ExecutionResult {
            exit_code: 1,
            signal: None,
            stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100,
            http_status: None,
            peak_rss_kb: None,
            cpu_user_ms: None,
            cpu_sys_ms: None,
            core_dumped: false,
            timed_out: false,
            max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };

        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());

        // Non-zero exit should have fitness >= 10
        assert!(score.total >= 10.0);
        assert!(score.components.contains_key("exit_code"));
    }

    #[test]
    fn test_timing_anomaly_fitness() {
        let scorer = CurlFitnessScorer::default();

        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 500, // Much higher than mean
            http_status: Some(200),
            peak_rss_kb: None,
            cpu_user_ms: None,
            cpu_sys_ms: None,
            core_dumped: false,
            timed_out: false,
            max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };

        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());

        // Should have timing component
        // z_score = (500 - 100) / 20 = 20, so timing = 5.0 * min(20 - 2, 10) = 5.0 * 10 = 50.0
        assert!(score.total > 0.0);
        assert!(score.components.contains_key("timing"));
    }

    #[test]
    fn test_stderr_warning_fitness() {
        let scorer = CurlFitnessScorer::default();

        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: "".to_string(),
            stderr: "WARNING: Something happened".to_string(),
            duration_ms: 100,
            http_status: Some(200),
            peak_rss_kb: None,
            cpu_user_ms: None,
            cpu_sys_ms: None,
            core_dumped: false,
            timed_out: false,
            max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };

        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());

        // Should have stderr component
        assert!(score.components.contains_key("stderr"));
        assert!(score.total >= 3.0);
    }

    #[test]
    fn test_http_500_anomaly() {
        let scorer = CurlFitnessScorer::default();

        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100,
            http_status: Some(500),
            peak_rss_kb: None,
            cpu_user_ms: None,
            cpu_sys_ms: None,
            core_dumped: false,
            timed_out: false,
            max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };

        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());

        // Should have http_anomaly component
        assert!(score.components.contains_key("http_anomaly"));
        assert!(score.total >= 2.0);
    }

    #[test]
    fn test_http_zero_anomaly() {
        let scorer = CurlFitnessScorer::default();

        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100,
            http_status: Some(0),
            peak_rss_kb: None,
            cpu_user_ms: None,
            cpu_sys_ms: None,
            core_dumped: false,
            timed_out: false,
            max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };

        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());

        // Should have http_anomaly component
        assert!(score.components.contains_key("http_anomaly"));
        assert!(score.total >= 2.0);
    }

    #[test]
    fn test_multiple_components() {
        let scorer = CurlFitnessScorer::default();

        let result = ExecutionResult {
            exit_code: 1,
            signal: None,
            stdout: "".to_string(),
            stderr: "error: connection failed".to_string(),
            duration_ms: 100,
            http_status: Some(500),
            peak_rss_kb: None,
            cpu_user_ms: None,
            cpu_sys_ms: None,
            core_dumped: false,
            timed_out: false,
            max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };

        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());

        // Should have multiple components
        assert!(score.components.contains_key("exit_code"));
        assert!(score.components.contains_key("stderr"));
        assert!(score.components.contains_key("http_anomaly"));
        // Total should be sum: 10 + 3 + 2 = 15
        assert_eq!(score.total, 15.0);
    }

    #[test]
    fn test_high_memory_fitness() {
        let scorer = CurlFitnessScorer::default();

        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100,
            http_status: Some(200),
            peak_rss_kb: Some(500_000), // 500MB - way above baseline
            cpu_user_ms: None,
            cpu_sys_ms: None,
            core_dumped: false,
            timed_out: false,
            max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };

        let baselines = Baselines {
            mean_rss: 10_000.0,   // 10MB typical
            stddev_rss: 5_000.0,  // 5MB stddev
            ..Default::default()
        };

        let score = scorer.score(&result, &baselines, &ScoringContext::default());
        assert!(score.components.contains_key("memory"));
        assert!(score.total > 0.0);
    }

    #[test]
    fn test_high_cpu_fitness() {
        let scorer = CurlFitnessScorer::default();

        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100,
            http_status: Some(200),
            peak_rss_kb: None,
            cpu_user_ms: Some(5000),  // 5 seconds of CPU
            cpu_sys_ms: Some(2000),   // 2 seconds of sys CPU
            core_dumped: false,
            timed_out: false,
            max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };

        let baselines = Baselines {
            mean_cpu: 50.0,    // 50ms typical
            stddev_cpu: 20.0,  // 20ms stddev
            ..Default::default()
        };

        let score = scorer.score(&result, &baselines, &ScoringContext::default());
        assert!(score.components.contains_key("cpu"));
        assert!(score.total > 0.0);
    }

    #[test]
    fn test_running_stats() {
        let mut stats = RunningStats::new();
        stats.update(10.0);
        stats.update(20.0);
        stats.update(30.0);

        assert!((stats.mean() - 20.0).abs() < 0.001);
        assert!(stats.stddev() > 0.0);
    }

    #[test]
    fn test_protocol_expectations_default() {
        let expectations = ProtocolExpectations::default();
        assert_eq!(expectations.normal_exit_codes, vec![0]);
        assert_eq!(expectations.timeout_baseline_ms, 5000);
    }

    #[test]
    fn test_per_protocol_baselines() {
        let mut tracker = PerProtocolBaselines::new();
        tracker.update("http", 100.0, None, None, 50.0, 200.0, None);
        tracker.update("http", 200.0, None, None, 60.0, 300.0, None);
        tracker.update("ftp", 500.0, None, None, 10.0, 50.0, None);

        let http_baselines = tracker.baselines_for("http");
        assert!((http_baselines.mean_duration - 150.0).abs() < 1.0);

        let ftp_baselines = tracker.baselines_for("ftp");
        assert!((ftp_baselines.mean_duration - 500.0).abs() < 1.0);
    }

    #[test]
    fn test_per_protocol_baselines_unknown_protocol() {
        let tracker = PerProtocolBaselines::new();
        let baselines = tracker.baselines_for("unknown");
        // Should return defaults
        assert_eq!(baselines.mean_duration, 100.0);
        assert_eq!(baselines.total_runs, 0);
    }

    #[test]
    fn test_diversity_bonus_calculation() {
        use std::collections::HashMap;
        let protocol_counts: HashMap<String, usize> = [
            ("http".into(), 3),
            ("ftp".into(), 1),
        ].into();
        let http_bonus = diversity_bonus("http", &protocol_counts, 1.0);
        let ftp_bonus = diversity_bonus("ftp", &protocol_counts, 1.0);
        assert!(ftp_bonus > http_bonus);
    }

    #[test]
    fn test_stderr_novelty_scoring() {
        let mut scorer = CurlFitnessScorer::default();
        scorer.stderr_novelty_weight = 5.0;
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "some novel error".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false,
            max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };
        let ctx = ScoringContext { stderr_novel: true, new_coverage_edges: None, verbose_anomaly_score: 0.0, verbose_labels: vec![], nondeterminism_score: 0.0 };
        let score = scorer.score(&result, &Baselines::default(), &ctx);
        assert!(score.components.contains_key("stderr_novelty"));
        assert_eq!(*score.components.get("stderr_novelty").unwrap(), 5.0);
    }

    #[test]
    fn test_stderr_not_novel() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "seen before".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false,
            max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };
        let ctx = ScoringContext { stderr_novel: false, new_coverage_edges: None, verbose_anomaly_score: 0.0, verbose_labels: vec![], nondeterminism_score: 0.0 };
        let score = scorer.score(&result, &Baselines::default(), &ctx);
        assert!(!score.components.contains_key("stderr_novelty"));
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        // All same bytes -> entropy 0
        let data = vec![0x41u8; 100];
        assert!((shannon_entropy(&data) - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_shannon_entropy_random() {
        // All 256 byte values equally -> entropy ~8.0
        let data: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&data) - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_high_entropy_stdout_scores() {
        let mut scorer = CurlFitnessScorer::default();
        scorer.entropy_weight = 5.0;
        // Create high-entropy data (random-ish bytes)
        let high_entropy: String = (0..200).map(|i| ((i * 37 + 13) % 256) as u8 as char).collect();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: high_entropy,
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false,
            max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };
        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());
        // High entropy should trigger entropy_high component
        assert!(score.components.contains_key("entropy_high"));
    }

    #[test]
    fn test_fd_leak_scoring() {
        let mut scorer = CurlFitnessScorer::default();
        scorer.fd_leak_weight = 5.0;
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false,
            max_fd_count: Some(500), server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };
        let baselines = Baselines {
            mean_fd_count: 10.0,
            stddev_fd_count: 5.0,
            ..Default::default()
        };
        let score = scorer.score(&result, &baselines, &ScoringContext::default());
        assert!(score.components.contains_key("fd_leak"));
        assert!(score.total > 0.0);
    }

    #[test]
    fn test_coverage_scoring() {
        let mut scorer = CurlFitnessScorer::default();
        scorer.coverage_weight = 10.0;
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };
        let ctx = ScoringContext { stderr_novel: false, new_coverage_edges: Some(50), verbose_anomaly_score: 0.0, verbose_labels: vec![], nondeterminism_score: 0.0 };
        let score = scorer.score(&result, &Baselines::default(), &ctx);
        assert!(score.components.contains_key("coverage"));
        assert!(score.total > 10.0); // 10 * (1 + ln(50)) ≈ 49
    }

    #[test]
    fn test_no_coverage_no_score() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };
        let ctx = ScoringContext { stderr_novel: false, new_coverage_edges: None, verbose_anomaly_score: 0.0, verbose_labels: vec![], nondeterminism_score: 0.0 };
        let score = scorer.score(&result, &Baselines::default(), &ctx);
        assert!(!score.components.contains_key("coverage"));
    }

    #[test]
    fn test_verbose_anomaly_scoring() {
        let mut scorer = CurlFitnessScorer::default();
        scorer.verbose_anomaly_weight = 4.0;
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };
        let ctx = ScoringContext {
            stderr_novel: false,
            new_coverage_edges: None,
            verbose_anomaly_score: 0.8,
            verbose_labels: vec!["partial_tls"],
            nondeterminism_score: 0.0,
        };
        let score = scorer.score(&result, &Baselines::default(), &ctx);
        assert!(score.components.contains_key("verbose_anomaly"));
        // 4.0 * 0.8 = 3.2
        let v = *score.components.get("verbose_anomaly").unwrap();
        assert!((v - 3.2).abs() < 0.01);
    }

    #[test]
    fn test_no_verbose_anomaly() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };
        let ctx = ScoringContext::default();
        let score = scorer.score(&result, &Baselines::default(), &ctx);
        assert!(!score.components.contains_key("verbose_anomaly"));
    }

    #[test]
    fn test_timing_breakdown_server_delay() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None,
            write_out: CurlWriteOut {
                time_connect: Some(0.01),
                time_starttransfer: Some(0.95),  // 95% of total = server delay
                time_total: Some(1.0),
                ..Default::default()
            },
            coverage_edges: vec![],
        };
        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());
        assert!(score.components.contains_key("timing_breakdown"),
            "Server delay should trigger timing_breakdown, components: {:?}", score.components);
    }

    #[test]
    fn test_timing_breakdown_normal() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None,
            write_out: CurlWriteOut {
                time_connect: Some(0.01),
                time_starttransfer: Some(0.02),
                time_total: Some(0.05),
                ..Default::default()
            },
            coverage_edges: vec![],
        };
        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());
        assert!(!score.components.contains_key("timing_breakdown"));
    }

    #[test]
    fn test_timing_breakdown_tls_stall() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 1000, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None,
            write_out: CurlWriteOut {
                time_connect: Some(0.01),
                time_appconnect: Some(0.8),  // TLS took 80% of total
                time_starttransfer: Some(0.85),
                time_total: Some(1.0),
                ..Default::default()
            },
            coverage_edges: vec![],
        };
        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());
        assert!(score.components.contains_key("timing_breakdown"),
            "TLS stall should trigger timing_breakdown");
    }

    #[test]
    fn test_size_ratio_amplification() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None,
            write_out: CurlWriteOut {
                size_request: Some(50),
                size_download: Some(50000),  // 1000x amplification
                ..Default::default()
            },
            coverage_edges: vec![],
        };
        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());
        assert!(score.components.contains_key("size_ratio"),
            "1000x amplification should trigger size_ratio");
    }

    #[test]
    fn test_size_ratio_suppression() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None,
            write_out: CurlWriteOut {
                size_request: Some(500),
                size_download: Some(0),  // Large request, empty response
                ..Default::default()
            },
            coverage_edges: vec![],
        };
        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());
        assert!(score.components.contains_key("size_ratio"),
            "Large request with zero response should trigger size_ratio");
    }

    #[test]
    fn test_size_ratio_normal() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None,
            write_out: CurlWriteOut {
                size_request: Some(100),
                size_download: Some(500),  // 5x is normal
                ..Default::default()
            },
            coverage_edges: vec![],
        };
        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());
        assert!(!score.components.contains_key("size_ratio"));
    }

    #[test]
    fn test_redirect_deep_chain() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None,
            write_out: CurlWriteOut {
                num_redirects: Some(5),
                ..Default::default()
            },
            coverage_edges: vec![],
        };
        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());
        assert!(score.components.contains_key("redirect"),
            "5 redirects should trigger redirect signal");
    }

    #[test]
    fn test_redirect_protocol_switch() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(301),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None,
            write_out: CurlWriteOut {
                num_redirects: Some(1),
                scheme: Some("https".to_string()),
                redirect_url: Some("ftp://evil.com/malware".to_string()),
                ..Default::default()
            },
            coverage_edges: vec![],
        };
        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());
        assert!(score.components.contains_key("redirect"),
            "Protocol-switching redirect should trigger redirect signal");
    }

    #[test]
    fn test_redirect_loop_timeout() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 5000, http_status: None,
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: true, max_fd_count: None, server_malformation: None,
            write_out: CurlWriteOut {
                num_redirects: Some(10),
                ..Default::default()
            },
            coverage_edges: vec![],
        };
        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());
        assert!(score.components.contains_key("redirect"),
            "Redirect loop with timeout should trigger redirect signal");
    }

    #[test]
    fn test_no_redirects_no_score() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None,
            write_out: CurlWriteOut {
                num_redirects: Some(0),
                ..Default::default()
            },
            coverage_edges: vec![],
        };
        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());
        assert!(!score.components.contains_key("redirect"));
    }

    #[test]
    fn test_nondeterminism_scoring() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 56, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: None,
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };
        let ctx = ScoringContext {
            nondeterminism_score: 0.5,
            ..Default::default()
        };
        let score = scorer.score(&result, &Baselines::default(), &ctx);
        assert!(score.components.contains_key("nondeterminism"),
            "Non-determinism should be scored when detected");
        let v = *score.components.get("nondeterminism").unwrap();
        assert!((v - 10.0).abs() < 0.01, "Expected 20.0 * 0.5 = 10.0, got {}", v);
    }

    #[test]
    fn test_no_nondeterminism() {
        let scorer = CurlFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0, signal: None, stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100, http_status: Some(200),
            peak_rss_kb: None, cpu_user_ms: None, cpu_sys_ms: None,
            core_dumped: false, timed_out: false, max_fd_count: None, server_malformation: None, write_out: Default::default(),
            coverage_edges: vec![],
        };
        let score = scorer.score(&result, &Baselines::default(), &ScoringContext::default());
        assert!(!score.components.contains_key("nondeterminism"));
    }

    #[test]
    fn test_coverage_evaluator_fields() {
        // Verify evaluator can be constructed with coverage fields
        let evaluator = CurlFitnessEvaluator::new(
            "curl".to_string(),
            "http://localhost".to_string(),
            3000,
            CurlFitnessScorer::default(),
        );
        assert!(evaluator.coverage_enabled);
        assert_eq!(evaluator.gcov_strip_count, 5);
        assert!(!evaluator.gcov_source_root.is_empty());
    }
}
