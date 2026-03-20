use crate::executor::ExecutionResult;
use crate::individual::OpenSslIndividual;
use crate::tls_state;
use ga_engine::fitness::FitnessScore;
use ga_engine::traits::FitnessEvaluator;

pub struct OpenSslFitnessScorer {
    pub crash_weight: f64,
    pub sanitizer_weight: f64,
    pub exit_code_weight: f64,
    pub timing_weight: f64,
    pub tls_anomaly_weight: f64,
    pub memory_weight: f64,
    pub stderr_novelty_weight: f64,
    pub exit_rarity_weight: f64,
    pub fd_leak_weight: f64,
    pub cpu_weight: f64,
}

impl Default for OpenSslFitnessScorer {
    fn default() -> Self {
        Self {
            crash_weight: 100.0,
            sanitizer_weight: 200.0,
            exit_code_weight: 10.0,
            timing_weight: 5.0,
            tls_anomaly_weight: 15.0,
            memory_weight: 8.0,
            stderr_novelty_weight: 5.0,
            exit_rarity_weight: 5.0,
            fd_leak_weight: 5.0,
            cpu_weight: 1.5,
        }
    }
}

/// Running statistics using Welford's online algorithm
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

/// Normalize stderr for novelty tracking: strip numbers, PIDs, addresses, paths.
fn stderr_key(stderr: &str) -> String {
    let mut key = String::with_capacity(stderr.len().min(256));
    for line in stderr.lines().take(20) {
        let normalized = line
            .replace(|c: char| c.is_ascii_digit(), "#")
            .replace("/home/", "/PATH/")
            .replace("/tmp/", "/PATH/");
        if !normalized.trim().is_empty() {
            if !key.is_empty() {
                key.push('|');
            }
            key.push_str(normalized.trim());
        }
    }
    key
}

impl OpenSslFitnessScorer {
    pub fn score(
        &self,
        result: &ExecutionResult,
        rss_stats: &RunningStats,
        fd_stats: &RunningStats,
        cpu_stats: &RunningStats,
        seen_stderr: &std::collections::HashSet<String>,
        exit_code_counts: &std::collections::HashMap<i32, usize>,
        total_evaluations: usize,
    ) -> FitnessScore {
        let mut components = Vec::new();

        // 1. Crash (signal) — skip if timed_out (SIGKILL from our watchdog)
        if let Some(signal) = result.signal {
            if !result.timed_out && signal != 9 {
                let severity = match signal {
                    11 => 1.0, // SIGSEGV
                    7  => 1.0, // SIGBUS
                    8  => 0.9, // SIGFPE
                    6  => 0.8, // SIGABRT
                    4  => 0.7, // SIGILL
                    _  => 0.3,
                };
                components.push(("crash", self.crash_weight * severity));
            }
        }

        // 2. Sanitizer output
        let stderr_lower = result.stderr.to_lowercase();
        if stderr_lower.contains("addresssanitizer")
            || stderr_lower.contains("leaksanitizer")
            || stderr_lower.contains("ubsan")
            || stderr_lower.contains("memorysanitizer")
            || stderr_lower.contains("threadsanitizer")
            || stderr_lower.contains("runtime error:")
        {
            let severity = if stderr_lower.contains("heap-buffer-overflow")
                || stderr_lower.contains("stack-buffer-overflow")
                || stderr_lower.contains("use-after-free")
                || stderr_lower.contains("double-free")
            {
                1.0
            } else if stderr_lower.contains("heap-use-after-free")
                || stderr_lower.contains("stack-use-after-return")
            {
                0.9
            } else if stderr_lower.contains("leak") {
                0.5
            } else {
                0.7
            };
            components.push(("sanitizer", self.sanitizer_weight * severity));
        }

        // 3. Exit code
        if result.signal.is_none() && result.exit_code != 0 {
            let interest = match result.exit_code {
                1 => 0.3,  // Normal TLS error
                _ => 1.0,  // Unexpected exit code
            };
            components.push(("exit_code", self.exit_code_weight * interest));
        }

        // 4. Timing anomaly (handshake >2s is suspicious)
        if result.duration_ms > 2000 {
            let excess_seconds = (result.duration_ms as f64 - 2000.0) / 1000.0;
            let score = self.timing_weight * (1.0 + excess_seconds).ln().max(0.0);
            components.push(("timing", score));
        }

        // 5. TLS handshake state anomaly (uncapped — more anomalies = more interesting)
        let tls_analysis = tls_state::analyze_tls(&result.stdout, &result.stderr);
        if tls_analysis.anomaly_score > 0.0 {
            let score = self.tls_anomaly_weight * tls_analysis.anomaly_score;
            components.push(("tls_anomaly", score));
        }

        // 6. Memory anomaly: high RSS compared to baseline (log-scaled, no hard cap)
        if let Some(rss) = result.peak_rss_kb {
            let stddev = rss_stats.stddev();
            if stddev > 0.0 {
                let z_score = (rss as f64 - rss_stats.mean()) / stddev;
                if z_score > 2.0 {
                    let mem_score = self.memory_weight * (z_score - 1.0).ln();
                    components.push(("memory", mem_score));
                }
            }
        }

        // 7. FD leak detection
        if let Some(fd_count) = result.max_fd_count {
            let stddev = fd_stats.stddev();
            if stddev > 0.0 {
                let z_score = (fd_count as f64 - fd_stats.mean()) / stddev;
                if z_score > 2.0 {
                    let fd_score = self.fd_leak_weight * (z_score - 1.0).ln();
                    components.push(("fd_leak", fd_score));
                }
            }
        }

        // 8. CPU anomaly
        {
            let cpu_total = result.cpu_user_ms.unwrap_or(0) + result.cpu_sys_ms.unwrap_or(0);
            if cpu_total > 0 {
                let stddev = cpu_stats.stddev();
                if stddev > 0.0 {
                    let z_score = (cpu_total as f64 - cpu_stats.mean()) / stddev;
                    if z_score > 2.0 {
                        let cpu_score = self.cpu_weight * (z_score - 1.0).ln();
                        components.push(("cpu", cpu_score));
                    }
                }
            }
        }

        // 9. Stderr novelty: reward new stderr patterns
        let key = stderr_key(&result.stderr);
        if !key.is_empty() && !seen_stderr.contains(&key) {
            components.push(("stderr_novelty", self.stderr_novelty_weight));
        }

        // 10. Exit code rarity: reward uncommon exit codes
        if total_evaluations > 10 {
            let count = exit_code_counts.get(&result.exit_code).copied().unwrap_or(0);
            let freq = count as f64 / total_evaluations as f64;
            if freq < 0.1 {
                let rarity = (1.0 - freq * 10.0) * self.exit_rarity_weight;
                components.push(("exit_rarity", rarity));
            }
        }

        FitnessScore::from_weighted(&components)
    }
}

pub struct OpenSslFitnessEvaluator {
    pub openssl_path: String,
    pub connect: String,
    pub subcommand: String,
    pub fixed_args: Vec<String>,
    pub stdin_input: Option<String>,
    pub timeout_ms: u64,
    pub scorer: OpenSslFitnessScorer,
    pub rss_stats: std::sync::Mutex<RunningStats>,
    pub fd_stats: std::sync::Mutex<RunningStats>,
    pub cpu_stats: std::sync::Mutex<RunningStats>,
    pub seen_stderr: std::sync::Mutex<std::collections::HashSet<String>>,
    pub exit_code_counts: std::sync::Mutex<std::collections::HashMap<i32, usize>>,
    pub total_evaluations: std::sync::atomic::AtomicUsize,
    pub state_dir: Option<String>,
}

impl OpenSslFitnessEvaluator {
    pub fn new(openssl_path: String, connect: String, timeout_ms: u64) -> Self {
        Self::new_for_subcommand(
            openssl_path,
            "s_client".to_string(),
            vec!["-connect".to_string(), connect.clone(), "-no-interactive".to_string()],
            Some("Q\n".to_string()),
            timeout_ms,
        )
    }

    pub fn new_for_subcommand(
        openssl_path: String,
        subcommand: String,
        fixed_args: Vec<String>,
        stdin_input: Option<String>,
        timeout_ms: u64,
    ) -> Self {
        Self {
            openssl_path,
            connect: String::new(),
            subcommand,
            fixed_args,
            stdin_input,
            timeout_ms,
            scorer: OpenSslFitnessScorer::default(),
            rss_stats: std::sync::Mutex::new(RunningStats::new()),
            fd_stats: std::sync::Mutex::new(RunningStats::new()),
            cpu_stats: std::sync::Mutex::new(RunningStats::new()),
            seen_stderr: std::sync::Mutex::new(std::collections::HashSet::new()),
            exit_code_counts: std::sync::Mutex::new(std::collections::HashMap::new()),
            total_evaluations: std::sync::atomic::AtomicUsize::new(0),
            state_dir: None,
        }
    }
}

impl FitnessEvaluator<OpenSslIndividual> for OpenSslFitnessEvaluator {
    fn evaluate(&self, individual: &OpenSslIndividual) -> FitnessScore {
        let args = individual.to_args();
        let result = match crate::executor::execute_openssl_cmd(
            &self.openssl_path, &self.subcommand, &self.fixed_args, &args,
            self.stdin_input.as_deref(), self.timeout_ms,
        ) {
            Ok(r) => r,
            Err(_) => return FitnessScore::new(0.0),
        };

        // Update running statistics
        if let Some(rss) = result.peak_rss_kb {
            self.rss_stats.lock().unwrap().update(rss as f64);
        }
        if let Some(fd) = result.max_fd_count {
            self.fd_stats.lock().unwrap().update(fd as f64);
        }
        {
            let cpu_total = result.cpu_user_ms.unwrap_or(0) + result.cpu_sys_ms.unwrap_or(0);
            if cpu_total > 0 {
                self.cpu_stats.lock().unwrap().update(cpu_total as f64);
            }
        }

        let total = self.total_evaluations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let rss_stats = self.rss_stats.lock().unwrap();
        let fd_stats = self.fd_stats.lock().unwrap();
        let cpu_stats = self.cpu_stats.lock().unwrap();
        let seen_stderr = self.seen_stderr.lock().unwrap();
        let exit_code_counts = self.exit_code_counts.lock().unwrap();

        let mut score = self.scorer.score(
            &result, &rss_stats, &fd_stats, &cpu_stats,
            &seen_stderr, &exit_code_counts, total,
        );

        drop(rss_stats);
        drop(fd_stats);
        drop(cpu_stats);
        drop(seen_stderr);
        drop(exit_code_counts);

        // Update tracking state after scoring (so first occurrence gets novelty bonus)
        let key = stderr_key(&result.stderr);
        if !key.is_empty() {
            self.seen_stderr.lock().unwrap().insert(key);
        }
        *self.exit_code_counts.lock().unwrap().entry(result.exit_code).or_insert(0) += 1;

        // Read server malformation state file if available
        if let Some(ref state_dir) = self.state_dir {
            let state_file = std::path::Path::new(state_dir).join("tls.state");
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
    use std::collections::{HashMap, HashSet};

    fn make_result(exit_code: i32, signal: Option<i32>, stderr: &str, duration_ms: u64) -> ExecutionResult {
        ExecutionResult {
            exit_code,
            signal,
            stdout: String::new(),
            stderr: stderr.to_string(),
            duration_ms,
            timed_out: false,
            peak_rss_kb: None,
            cpu_user_ms: None,
            cpu_sys_ms: None,
            max_fd_count: None,
        }
    }

    fn empty_rss_stats() -> RunningStats {
        RunningStats::new()
    }

    fn empty_fd_stats() -> RunningStats {
        RunningStats::new()
    }

    fn empty_cpu_stats() -> RunningStats {
        RunningStats::new()
    }

    fn empty_seen() -> HashSet<String> {
        HashSet::new()
    }

    fn empty_exit_counts() -> HashMap<i32, usize> {
        HashMap::new()
    }

    fn score_simple(scorer: &OpenSslFitnessScorer, result: &ExecutionResult) -> FitnessScore {
        scorer.score(result, &empty_rss_stats(), &empty_fd_stats(), &empty_cpu_stats(), &empty_seen(), &empty_exit_counts(), 0)
    }

    fn score_with_rss(scorer: &OpenSslFitnessScorer, result: &ExecutionResult, rss: &RunningStats) -> FitnessScore {
        scorer.score(result, rss, &empty_fd_stats(), &empty_cpu_stats(), &empty_seen(), &empty_exit_counts(), 0)
    }

    #[test]
    fn test_normal_execution() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(0, None, "", 100);
        let score = score_simple(&scorer, &result);
        assert!(score.total < 1.0);
    }

    #[test]
    fn test_crash_sigsegv() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(-1, Some(11), "", 5);
        let score = score_simple(&scorer, &result);
        assert!(score.total >= 100.0);
        assert!(score.components.contains_key("crash"));
    }

    #[test]
    fn test_crash_sigabrt() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(-1, Some(6), "", 5);
        let score = score_simple(&scorer, &result);
        assert_eq!(*score.components.get("crash").unwrap(), 100.0 * 0.8);
    }

    #[test]
    fn test_sanitizer_asan() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(1, None, "==12345==ERROR: AddressSanitizer: heap-buffer-overflow", 50);
        let score = score_simple(&scorer, &result);
        assert!(score.components.contains_key("sanitizer"));
        assert_eq!(*score.components.get("sanitizer").unwrap(), 200.0);
    }

    #[test]
    fn test_sanitizer_leak() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(1, None, "==12345==ERROR: LeakSanitizer: detected memory leaks", 50);
        let score = score_simple(&scorer, &result);
        assert!(score.components.contains_key("sanitizer"));
        assert_eq!(*score.components.get("sanitizer").unwrap(), 200.0 * 0.5);
    }

    #[test]
    fn test_sanitizer_ubsan() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(0, None, "runtime error: signed integer overflow", 50);
        let score = score_simple(&scorer, &result);
        assert!(score.components.contains_key("sanitizer"));
    }

    #[test]
    fn test_crash_sigkill_ignored() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(-1, Some(9), "", 5);
        let score = score_simple(&scorer, &result);
        assert!(!score.components.contains_key("crash"),
            "SIGKILL should not be scored as crash (it comes from external sources)");
    }

    #[test]
    fn test_crash_timed_out_ignored() {
        let scorer = OpenSslFitnessScorer::default();
        let mut result = make_result(-1, Some(9), "", 5000);
        result.timed_out = true;
        let score = score_simple(&scorer, &result);
        assert!(!score.components.contains_key("crash"),
            "Watchdog-killed processes should not score as crash");
    }

    #[test]
    fn test_exit_code_1_low_interest() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(1, None, "", 100);
        let score = score_simple(&scorer, &result);
        assert_eq!(*score.components.get("exit_code").unwrap(), 10.0 * 0.3);
    }

    #[test]
    fn test_exit_code_unexpected() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(42, None, "", 100);
        let score = score_simple(&scorer, &result);
        assert_eq!(*score.components.get("exit_code").unwrap(), 10.0);
    }

    #[test]
    fn test_timing_anomaly() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(0, None, "", 5000);
        let score = score_simple(&scorer, &result);
        assert!(score.components.contains_key("timing"));
    }

    #[test]
    fn test_no_timing_under_threshold() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(0, None, "", 1500);
        let score = score_simple(&scorer, &result);
        assert!(!score.components.contains_key("timing"));
    }

    #[test]
    fn test_multiple_signals() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(-1, Some(11), "AddressSanitizer: heap-buffer-overflow", 5);
        let score = score_simple(&scorer, &result);
        assert!(score.components.contains_key("crash"));
        assert!(score.components.contains_key("sanitizer"));
        assert!(score.total >= 300.0);
    }

    #[test]
    fn test_tls_anomaly_incomplete_handshake() {
        let scorer = OpenSslFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 1,
            signal: None,
            stdout: "CONNECTED(00000003)\n".to_string(),
            stderr: "".to_string(),
            duration_ms: 100,
            timed_out: false,
            peak_rss_kb: None,
            cpu_user_ms: None, cpu_sys_ms: None, max_fd_count: None,
        };
        let score = score_simple(&scorer, &result);
        assert!(score.components.contains_key("tls_anomaly"));
    }

    #[test]
    fn test_tls_anomaly_legacy_protocol() {
        let scorer = OpenSslFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: "CONNECTED(00000003)\nSSL handshake has read 1234 bytes\nProtocol  : SSLv3\nCipher    : DES-CBC3-SHA\nVerify return code: 0 (ok)\n".to_string(),
            stderr: "".to_string(),
            duration_ms: 100,
            timed_out: false,
            peak_rss_kb: None,
            cpu_user_ms: None, cpu_sys_ms: None, max_fd_count: None,
        };
        let score = score_simple(&scorer, &result);
        assert!(score.components.contains_key("tls_anomaly"));
    }

    #[test]
    fn test_tls_anomaly_uncapped() {
        // Verify that multiple TLS anomalies accumulate beyond the old 3.0 cap
        let scorer = OpenSslFitnessScorer::default();
        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: "CONNECTED(00000003)\nProtocol  : SSLv3\nCipher    : NULL-SHA\nRENEGOTIATING\n".to_string(),
            stderr: "SSL alert: sslv3 alert internal_error\n".to_string(),
            duration_ms: 100,
            timed_out: false,
            peak_rss_kb: None,
            cpu_user_ms: None, cpu_sys_ms: None, max_fd_count: None,
        };
        let score = score_simple(&scorer, &result);
        // incomplete_handshake(0.6) + legacy_protocol(0.7) + weak_cipher(0.8) + renegotiation(0.5) + interesting_alert(0.6) = 3.2
        // Old cap would limit to 3.0 × 15 = 45. Now should be 3.2 × 15 = 48
        assert!(score.components.get("tls_anomaly").unwrap() > &45.0,
            "TLS anomaly should exceed old cap, got {}", score.components.get("tls_anomaly").unwrap());
    }

    #[test]
    fn test_memory_anomaly() {
        let scorer = OpenSslFitnessScorer::default();

        let mut rss_stats = RunningStats::new();
        for &v in &[9000.0, 10000.0, 11000.0, 10500.0, 9500.0, 10000.0, 10200.0, 9800.0] {
            rss_stats.update(v);
        }

        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 100,
            timed_out: false,
            peak_rss_kb: Some(50000),
            cpu_user_ms: None, cpu_sys_ms: None, max_fd_count: None,
        };
        let score = score_with_rss(&scorer, &result, &rss_stats);
        assert!(score.components.contains_key("memory"), "Expected memory anomaly signal");
    }

    #[test]
    fn test_no_memory_anomaly_within_baseline() {
        let scorer = OpenSslFitnessScorer::default();

        let mut rss_stats = RunningStats::new();
        for &v in &[9000.0, 10000.0, 11000.0, 10500.0, 9500.0, 10000.0] {
            rss_stats.update(v);
        }

        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 100,
            timed_out: false,
            peak_rss_kb: Some(10500),
            cpu_user_ms: None, cpu_sys_ms: None, max_fd_count: None,
        };
        let score = score_with_rss(&scorer, &result, &rss_stats);
        assert!(!score.components.contains_key("memory"));
    }

    #[test]
    fn test_stderr_novelty() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(1, None, "error: something went wrong", 100);
        let seen = HashSet::new(); // empty — first time seeing this
        let score = scorer.score(&result, &empty_rss_stats(), &empty_fd_stats(), &empty_cpu_stats(), &seen, &empty_exit_counts(), 0);
        assert!(score.components.contains_key("stderr_novelty"));
    }

    #[test]
    fn test_stderr_novelty_already_seen() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(1, None, "error: something went wrong", 100);
        let key = stderr_key("error: something went wrong");
        let mut seen = HashSet::new();
        seen.insert(key);
        let score = scorer.score(&result, &empty_rss_stats(), &empty_fd_stats(), &empty_cpu_stats(), &seen, &empty_exit_counts(), 0);
        assert!(!score.components.contains_key("stderr_novelty"));
    }

    #[test]
    fn test_exit_code_rarity() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(42, None, "", 100);
        // exit code 42 never seen before, but need >10 evaluations
        let mut counts = HashMap::new();
        counts.insert(0, 90);
        counts.insert(1, 10);
        // exit code 42 has 0 occurrences out of 100 → freq=0, rarity=5.0
        let score = scorer.score(&result, &empty_rss_stats(), &empty_fd_stats(), &empty_cpu_stats(), &empty_seen(), &counts, 100);
        assert!(score.components.contains_key("exit_rarity"));
    }

    #[test]
    fn test_exit_code_rarity_common_exit() {
        let scorer = OpenSslFitnessScorer::default();
        let result = make_result(0, None, "", 100);
        let mut counts = HashMap::new();
        counts.insert(0, 90); // exit 0 is 90% of results → freq=0.9 → no rarity bonus
        let score = scorer.score(&result, &empty_rss_stats(), &empty_fd_stats(), &empty_cpu_stats(), &empty_seen(), &counts, 100);
        assert!(!score.components.contains_key("exit_rarity"));
    }

    #[test]
    fn test_stderr_key_normalization() {
        let key1 = stderr_key("error at line 42: connection to 127.0.0.1:8443 failed");
        let key2 = stderr_key("error at line 99: connection to 127.0.0.1:8443 failed");
        assert_eq!(key1, key2, "Numbers should be normalized to #");
    }
}
