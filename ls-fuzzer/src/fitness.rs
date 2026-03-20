use crate::executor::ExecutionResult;
use crate::individual::LsIndividual;
use ga_engine::fitness::FitnessScore;
use ga_engine::traits::FitnessEvaluator;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Welford's online algorithm for running mean/stddev
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
            return 0.0;
        }
        (self.m2 / (self.count - 1) as f64).sqrt()
    }

    pub fn count(&self) -> u64 {
        self.count
    }
}

pub struct LsFitnessScorer {
    pub crash_weight: f64,
    pub exit_code_weight: f64,
    pub stderr_weight: f64,
    pub timing_weight: f64,
    pub output_anomaly_weight: f64,
    pub memory_weight: f64,
    pub stderr_novelty_weight: f64,
    pub exit_rarity_weight: f64,
}

impl Default for LsFitnessScorer {
    fn default() -> Self {
        Self {
            crash_weight: 100.0,
            exit_code_weight: 5.0,
            stderr_weight: 3.0,
            timing_weight: 5.0,
            output_anomaly_weight: 2.0,
            memory_weight: 8.0,
            stderr_novelty_weight: 3.0,
            exit_rarity_weight: 3.0,
        }
    }
}

impl LsFitnessScorer {
    pub fn score(
        &self,
        result: &ExecutionResult,
        rss_stats: &RunningStats,
        seen_stderr: &HashSet<String>,
        exit_code_counts: &HashMap<i32, usize>,
        total_evaluations: usize,
    ) -> FitnessScore {
        let mut components = Vec::new();

        // 1. Crash (signal)
        if let Some(signal) = result.signal {
            let severity = match signal {
                11 => 1.0,  // SIGSEGV
                7  => 1.0,  // SIGBUS
                8  => 0.9,  // SIGFPE
                6  => 0.8,  // SIGABRT
                4  => 0.7,  // SIGILL
                _  => 0.3,
            };
            components.push(("crash", self.crash_weight * severity));
        }

        // 2. Non-zero exit code (ls exit 2 = serious error, 1 = minor)
        if result.signal.is_none() && result.exit_code != 0 {
            let interest = match result.exit_code {
                2 => 2.0,   // Serious error
                1 => 0.5,   // Minor (e.g., can't access file)
                _ => 1.5,   // Unexpected exit code — very interesting
            };
            components.push(("exit_code", self.exit_code_weight * interest));
        }

        // 3. Stderr content analysis
        if !result.stderr.is_empty() {
            let stderr_lower = result.stderr.to_lowercase();
            if stderr_lower.contains("segfault")
                || stderr_lower.contains("abort")
                || stderr_lower.contains("overflow")
                || stderr_lower.contains("corrupt")
                || stderr_lower.contains("assertion")
            {
                components.push(("stderr_critical", self.stderr_weight * 3.0));
            } else if stderr_lower.contains("invalid")
                || stderr_lower.contains("unrecognized")
            {
                components.push(("stderr_error", self.stderr_weight));
            }
        }

        // 4. Timing anomaly (ls should be fast; >1s is suspicious)
        if result.duration_ms > 1000 {
            let excess_seconds = (result.duration_ms as f64 - 1000.0) / 1000.0;
            let score = self.timing_weight * (1.0 + excess_seconds).ln().max(0.0);
            components.push(("timing", score));
        }

        // 5. Output anomaly: extremely large output might indicate recursion issues
        if result.stdout.len() > 100_000 {
            let score = self.output_anomaly_weight * (result.stdout.len() as f64 / 100_000.0).min(5.0);
            components.push(("output_size", score));
        }

        // 6. Timeout
        if result.timed_out {
            components.push(("timeout", self.timing_weight * 2.0));
        }

        // 7. Memory anomaly — peak RSS > 2 stddev above baseline
        if let Some(rss_kb) = result.peak_rss_kb {
            if rss_stats.count() >= 5 {
                let stddev = rss_stats.stddev();
                if stddev > 0.0 {
                    let z = (rss_kb as f64 - rss_stats.mean()) / stddev;
                    if z > 2.0 {
                        let score = self.memory_weight * (z - 1.0).ln();
                        components.push(("memory", score));
                    }
                }
            }
        }

        // 8. Stderr novelty — first-seen stderr message scores higher
        if !result.stderr.is_empty() {
            let key = stderr_key(&result.stderr);
            if !seen_stderr.contains(&key) {
                components.push(("stderr_novelty", self.stderr_novelty_weight));
            }
        }

        // 9. Exit code rarity — rare exit codes score higher
        if total_evaluations > 10 {
            let count = exit_code_counts.get(&result.exit_code).copied().unwrap_or(0);
            let frequency = count as f64 / total_evaluations as f64;
            if frequency < 0.1 {
                // Rare: seen in < 10% of evaluations
                let score = self.exit_rarity_weight * (1.0 - frequency * 10.0);
                components.push(("exit_rarity", score));
            }
        }

        FitnessScore::from_weighted(&components)
    }
}

/// Normalize stderr to a key for novelty tracking.
/// Takes the first non-empty line, strips numbers and paths to group similar messages.
fn stderr_key(stderr: &str) -> String {
    let first_line = stderr.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    // Strip numbers and paths to group similar messages
    first_line
        .chars()
        .map(|c| if c.is_ascii_digit() { '#' } else { c })
        .collect::<String>()
        .replace("/home/", "")
        .replace("/tmp/", "")
}

pub struct LsFitnessEvaluator {
    pub ls_path: String,
    pub target_path: String,
    pub timeout_ms: u64,
    pub scorer: LsFitnessScorer,
    rss_stats: Mutex<RunningStats>,
    seen_stderr: Mutex<HashSet<String>>,
    exit_code_counts: Mutex<HashMap<i32, usize>>,
    total_evaluations: Mutex<usize>,
}

impl LsFitnessEvaluator {
    pub fn new(ls_path: String, target_path: String, timeout_ms: u64) -> Self {
        Self {
            ls_path,
            target_path,
            timeout_ms,
            scorer: LsFitnessScorer::default(),
            rss_stats: Mutex::new(RunningStats::new()),
            seen_stderr: Mutex::new(HashSet::new()),
            exit_code_counts: Mutex::new(HashMap::new()),
            total_evaluations: Mutex::new(0),
        }
    }
}

impl FitnessEvaluator<LsIndividual> for LsFitnessEvaluator {
    fn evaluate(&self, individual: &LsIndividual) -> FitnessScore {
        let args = individual.to_args();
        let result = match crate::executor::execute_ls(
            &self.ls_path, &args, &self.target_path, self.timeout_ms,
        ) {
            Ok(r) => r,
            Err(_) => return FitnessScore::new(0.0),
        };

        if result.timed_out {
            return FitnessScore::new(0.0);
        }

        // Snapshot stats for scoring (read before updating)
        let rss_snapshot;
        let seen_snapshot;
        let exit_snapshot;
        let total_snapshot;

        {
            let rss = self.rss_stats.lock().unwrap();
            rss_snapshot = RunningStats {
                count: rss.count, mean: rss.mean, m2: rss.m2,
            };
        }
        {
            seen_snapshot = self.seen_stderr.lock().unwrap().clone();
        }
        {
            exit_snapshot = self.exit_code_counts.lock().unwrap().clone();
        }
        {
            total_snapshot = *self.total_evaluations.lock().unwrap();
        }

        let score = self.scorer.score(
            &result,
            &rss_snapshot,
            &seen_snapshot,
            &exit_snapshot,
            total_snapshot,
        );

        // Update stats after scoring
        if let Some(rss_kb) = result.peak_rss_kb {
            self.rss_stats.lock().unwrap().update(rss_kb as f64);
        }
        if !result.stderr.is_empty() {
            self.seen_stderr.lock().unwrap().insert(stderr_key(&result.stderr));
        }
        *self.exit_code_counts.lock().unwrap().entry(result.exit_code).or_insert(0) += 1;
        *self.total_evaluations.lock().unwrap() += 1;

        score
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(exit_code: i32, signal: Option<i32>, stderr: &str, duration_ms: u64) -> ExecutionResult {
        ExecutionResult {
            exit_code,
            signal,
            stdout: "".to_string(),
            stderr: stderr.to_string(),
            duration_ms,
            timed_out: false,
            peak_rss_kb: None,
        }
    }

    fn empty_stats() -> RunningStats {
        RunningStats::new()
    }

    fn baseline_rss_stats() -> RunningStats {
        let mut stats = RunningStats::new();
        // Simulate realistic RSS variance around 5MB
        for &v in &[4800.0, 5200.0, 4900.0, 5100.0, 5000.0,
                     4850.0, 5150.0, 4950.0, 5050.0, 5000.0,
                     4900.0, 5100.0, 4800.0, 5200.0, 4950.0,
                     5050.0, 5000.0, 4900.0, 5100.0, 5000.0] {
            stats.update(v);
        }
        stats
    }

    fn empty_seen() -> HashSet<String> {
        HashSet::new()
    }

    fn empty_exit_counts() -> HashMap<i32, usize> {
        HashMap::new()
    }

    #[test]
    fn test_normal_execution_low_fitness() {
        let scorer = LsFitnessScorer::default();
        let result = make_result(0, None, "", 5);
        let score = scorer.score(&result, &empty_stats(), &empty_seen(), &empty_exit_counts(), 0);
        assert!(score.total < 1.0);
    }

    #[test]
    fn test_crash_high_fitness() {
        let scorer = LsFitnessScorer::default();
        let result = make_result(-1, Some(11), "Segmentation fault", 5);
        let score = scorer.score(&result, &empty_stats(), &empty_seen(), &empty_exit_counts(), 0);
        assert!(score.total >= 100.0);
        assert!(score.components.contains_key("crash"));
    }

    #[test]
    fn test_exit_code_2_scored() {
        let scorer = LsFitnessScorer::default();
        let result = make_result(2, None, "serious error", 5);
        let score = scorer.score(&result, &empty_stats(), &empty_seen(), &empty_exit_counts(), 0);
        assert!(score.components.contains_key("exit_code"));
    }

    #[test]
    fn test_slow_execution_scored() {
        let scorer = LsFitnessScorer::default();
        let result = make_result(0, None, "", 3000);
        let score = scorer.score(&result, &empty_stats(), &empty_seen(), &empty_exit_counts(), 0);
        assert!(score.components.contains_key("timing"));
    }

    #[test]
    fn test_critical_stderr_scored() {
        let scorer = LsFitnessScorer::default();
        let result = make_result(1, None, "buffer overflow detected", 5);
        let score = scorer.score(&result, &empty_stats(), &empty_seen(), &empty_exit_counts(), 0);
        assert!(score.components.contains_key("stderr_critical"));
    }

    #[test]
    fn test_memory_anomaly() {
        let scorer = LsFitnessScorer::default();
        let stats = baseline_rss_stats();
        let mut result = make_result(0, None, "", 5);
        result.peak_rss_kb = Some(50_000); // 50MB — well above 5MB baseline
        let score = scorer.score(&result, &stats, &empty_seen(), &empty_exit_counts(), 0);
        assert!(score.components.contains_key("memory"), "Expected memory anomaly, got {:?}", score.components);
    }

    #[test]
    fn test_no_memory_anomaly_within_baseline() {
        let scorer = LsFitnessScorer::default();
        let stats = baseline_rss_stats();
        let mut result = make_result(0, None, "", 5);
        result.peak_rss_kb = Some(5100); // Just slightly above 5MB baseline
        let score = scorer.score(&result, &stats, &empty_seen(), &empty_exit_counts(), 0);
        assert!(!score.components.contains_key("memory"));
    }

    #[test]
    fn test_stderr_novelty() {
        let scorer = LsFitnessScorer::default();
        let seen = empty_seen();
        let result = make_result(1, None, "cannot access 'foo': No such file", 5);
        let score = scorer.score(&result, &empty_stats(), &seen, &empty_exit_counts(), 0);
        assert!(score.components.contains_key("stderr_novelty"));
    }

    #[test]
    fn test_stderr_not_novel() {
        let scorer = LsFitnessScorer::default();
        let result = make_result(1, None, "cannot access 'foo': No such file", 5);
        let key = stderr_key(&result.stderr);
        let mut seen = empty_seen();
        seen.insert(key);
        let score = scorer.score(&result, &empty_stats(), &seen, &empty_exit_counts(), 0);
        assert!(!score.components.contains_key("stderr_novelty"));
    }

    #[test]
    fn test_exit_code_rarity() {
        let scorer = LsFitnessScorer::default();
        // Exit code 2 seen 1 time out of 100 evaluations = 1% frequency
        let mut counts = HashMap::new();
        counts.insert(0, 95);
        counts.insert(1, 4);
        counts.insert(2, 1);
        let result = make_result(2, None, "", 5);
        let score = scorer.score(&result, &empty_stats(), &empty_seen(), &counts, 100);
        assert!(score.components.contains_key("exit_rarity"), "Expected exit_rarity, got {:?}", score.components);
    }

    #[test]
    fn test_exit_code_not_rare() {
        let scorer = LsFitnessScorer::default();
        // Exit code 0 seen 90 times out of 100 = 90% frequency (common)
        let mut counts = HashMap::new();
        counts.insert(0, 90);
        counts.insert(1, 10);
        let result = make_result(0, None, "", 5);
        let score = scorer.score(&result, &empty_stats(), &empty_seen(), &counts, 100);
        assert!(!score.components.contains_key("exit_rarity"));
    }

    #[test]
    fn test_running_stats() {
        let mut stats = RunningStats::new();
        stats.update(10.0);
        stats.update(20.0);
        stats.update(30.0);
        assert!((stats.mean() - 20.0).abs() < 0.01);
        assert!(stats.stddev() > 0.0);
        assert_eq!(stats.count(), 3);
    }

    #[test]
    fn test_stderr_key_normalizes() {
        let key1 = stderr_key("ls: cannot access '/tmp/test123': No such file");
        let key2 = stderr_key("ls: cannot access '/tmp/test456': No such file");
        assert_eq!(key1, key2, "Similar stderr messages should produce same key");
    }
}
