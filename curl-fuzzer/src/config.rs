use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMode {
    Good,
    Evil,
    Both,
}

impl std::fmt::Display for ServerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerMode::Good => write!(f, "good"),
            ServerMode::Evil => write!(f, "evil"),
            ServerMode::Both => write!(f, "both"),
        }
    }
}

impl std::str::FromStr for ServerMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "good" => Ok(ServerMode::Good),
            "evil" => Ok(ServerMode::Evil),
            "both" => Ok(ServerMode::Both),
            other => Err(format!(
                "Invalid server mode '{}'. Must be 'good', 'evil', or 'both'.", other
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FuzzerConfig {
    // GA parameters
    pub population_size: usize,
    pub max_generations: usize,
    pub mutation_rate: f64,
    pub crossover_rate: f64,
    pub elitism_percent: f64,
    pub seed: Option<u64>,

    // Curl parameters
    pub curl_path: String,
    pub timeout_ms: u64,
    pub target_url: String,
    pub flags_overlay_path: String,
    pub min_flags: usize,
    pub max_flags: usize,
    pub max_active_flags: usize,

    // Fitness weights
    pub weight_crash: f64,
    pub weight_exit_code: f64,
    pub weight_timing: f64,
    pub weight_stderr: f64,
    pub weight_http_anomaly: f64,
    pub weight_memory: f64,
    pub weight_cpu: f64,
    pub weight_core_dump: f64,
    pub weight_stderr_size: f64,
    pub weight_stdout_size: f64,
    pub weight_exit_rarity: f64,
    pub weight_sanitizer: f64,
    pub weight_stderr_novelty: f64,
    pub weight_entropy: f64,
    pub weight_fd_leak: f64,
    pub weight_coverage: f64,
    pub weight_verbose_anomaly: f64,
    pub weight_timing_breakdown: f64,
    pub weight_size_ratio: f64,
    pub weight_redirect: f64,
    pub weight_nondeterminism: f64,

    // Coverage-guided fitness
    pub coverage_enabled: bool,
    pub gcov_strip_count: u32,
    pub gcov_source_root: String,

    // Protocols
    pub enabled_protocols: Vec<String>,
    pub single_protocol: Option<String>,
    pub multi_protocols: Option<Vec<String>>,
    pub protocol_port_overrides: HashMap<String, u16>,
    pub blocking_timeout_s: u64,
    #[allow(dead_code)]
    pub weight_diversity: f64,

    // Servers
    pub start_servers: bool,
    pub server_mode: ServerMode,

    // Output
    pub database_path: String,
    pub findings_dir: String,
    pub fitness_threshold: f64,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            // GA defaults
            population_size: 50,
            max_generations: 15,
            mutation_rate: 0.02,
            crossover_rate: 0.3,
            elitism_percent: 0.1,
            seed: None,

            // Curl defaults
            curl_path: "curl".to_string(),
            timeout_ms: 3000,
            target_url: "http://localhost:8080".to_string(),
            flags_overlay_path: "config/curl-flags.toml".to_string(),
            min_flags: 5,
            max_flags: 30,
            max_active_flags: 35,

            // Fitness weights defaults
            weight_crash: 100.0,
            weight_exit_code: 10.0,
            weight_timing: 5.0,
            weight_stderr: 3.0,
            weight_http_anomaly: 2.0,
            weight_memory: 4.0,
            weight_cpu: 3.0,
            weight_core_dump: 150.0,
            weight_stderr_size: 2.0,
            weight_stdout_size: 2.0,
            weight_exit_rarity: 5.0,
            weight_sanitizer: 200.0,
            weight_stderr_novelty: 3.0,
            weight_entropy: 3.0,
            weight_fd_leak: 5.0,
            weight_coverage: 10.0,
            weight_verbose_anomaly: 4.0,
            weight_timing_breakdown: 6.0,
            weight_size_ratio: 4.0,
            weight_redirect: 5.0,
            weight_nondeterminism: 20.0,

            // Coverage defaults
            coverage_enabled: true,
            gcov_strip_count: 5,
            gcov_source_root: "/home/jfuller/src/curl".to_string(),

            // Protocols defaults
            enabled_protocols: vec!["http".into(), "https".into(), "ftp".into(), "smtp".into(), "imap".into()],
            single_protocol: None,
            multi_protocols: None,
            protocol_port_overrides: HashMap::new(),
            blocking_timeout_s: 5,
            weight_diversity: 1.0,

            // Servers defaults
            start_servers: true,
            server_mode: ServerMode::Both,

            // Output defaults
            database_path: "curl-fuzzer.db".to_string(),
            findings_dir: "curl-findings".to_string(),
            fitness_threshold: 25.0,
        }
    }
}

#[derive(Debug, Deserialize)]
struct TomlConfig {
    ga: Option<GaSection>,
    curl: Option<CurlSection>,
    fitness: Option<FitnessSection>,
    servers: Option<ServersSection>,
    protocols: Option<ProtocolsSection>,
    output: Option<OutputSection>,
    coverage: Option<CoverageSection>,
}

#[derive(Debug, Deserialize)]
struct GaSection {
    population_size: Option<usize>,
    max_generations: Option<usize>,
    mutation_rate: Option<f64>,
    crossover_rate: Option<f64>,
    elitism_percent: Option<f64>,
    seed: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct CurlSection {
    curl_path: Option<String>,
    timeout_ms: Option<u64>,
    target_url: Option<String>,
    flags_overlay_path: Option<String>,
    min_flags: Option<usize>,
    max_flags: Option<usize>,
    max_active_flags: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FitnessSection {
    weight_crash: Option<f64>,
    weight_exit_code: Option<f64>,
    weight_timing: Option<f64>,
    weight_stderr: Option<f64>,
    weight_http_anomaly: Option<f64>,
    weight_memory: Option<f64>,
    weight_cpu: Option<f64>,
    weight_core_dump: Option<f64>,
    weight_stderr_size: Option<f64>,
    weight_stdout_size: Option<f64>,
    weight_exit_rarity: Option<f64>,
    weight_sanitizer: Option<f64>,
    weight_stderr_novelty: Option<f64>,
    weight_entropy: Option<f64>,
    weight_fd_leak: Option<f64>,
    weight_coverage: Option<f64>,
    weight_verbose_anomaly: Option<f64>,
    weight_timing_breakdown: Option<f64>,
    weight_size_ratio: Option<f64>,
    weight_redirect: Option<f64>,
    weight_nondeterminism: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct ServersSection {
    start_servers: Option<bool>,
    server_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProtocolsSection {
    enabled: Option<Vec<String>>,
    blocking_timeout_s: Option<u64>,
    // Per-protocol port overrides are handled as a TOML table
}

#[derive(Debug, Deserialize)]
struct OutputSection {
    database_path: Option<String>,
    findings_dir: Option<String>,
    fitness_threshold: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct CoverageSection {
    enabled: Option<bool>,
    gcov_strip_count: Option<u32>,
    gcov_source_root: Option<String>,
}

impl FuzzerConfig {
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        let parsed: TomlConfig = toml::from_str(toml_str)?;
        let mut config = Self::default();

        // Apply GA overrides
        if let Some(ga) = parsed.ga {
            if let Some(v) = ga.population_size {
                config.population_size = v;
            }
            if let Some(v) = ga.max_generations {
                config.max_generations = v;
            }
            if let Some(v) = ga.mutation_rate {
                config.mutation_rate = v;
            }
            if let Some(v) = ga.crossover_rate {
                config.crossover_rate = v;
            }
            if let Some(v) = ga.elitism_percent {
                config.elitism_percent = v;
            }
            if let Some(v) = ga.seed {
                config.seed = Some(v);
            }
        }

        // Apply Curl overrides
        if let Some(curl) = parsed.curl {
            if let Some(v) = curl.curl_path {
                config.curl_path = v;
            }
            if let Some(v) = curl.timeout_ms {
                config.timeout_ms = v;
            }
            if let Some(v) = curl.target_url {
                config.target_url = v;
            }
            if let Some(v) = curl.flags_overlay_path {
                config.flags_overlay_path = v;
            }
            if let Some(v) = curl.min_flags {
                config.min_flags = v;
            }
            if let Some(v) = curl.max_flags {
                config.max_flags = v;
            }
            if let Some(v) = curl.max_active_flags {
                config.max_active_flags = v;
            }
        }

        // Apply Fitness overrides
        if let Some(fitness) = parsed.fitness {
            if let Some(v) = fitness.weight_crash {
                config.weight_crash = v;
            }
            if let Some(v) = fitness.weight_exit_code {
                config.weight_exit_code = v;
            }
            if let Some(v) = fitness.weight_timing {
                config.weight_timing = v;
            }
            if let Some(v) = fitness.weight_stderr {
                config.weight_stderr = v;
            }
            if let Some(v) = fitness.weight_http_anomaly {
                config.weight_http_anomaly = v;
            }
            if let Some(v) = fitness.weight_memory {
                config.weight_memory = v;
            }
            if let Some(v) = fitness.weight_cpu {
                config.weight_cpu = v;
            }
            if let Some(v) = fitness.weight_core_dump {
                config.weight_core_dump = v;
            }
            if let Some(v) = fitness.weight_stderr_size {
                config.weight_stderr_size = v;
            }
            if let Some(v) = fitness.weight_stdout_size {
                config.weight_stdout_size = v;
            }
            if let Some(v) = fitness.weight_exit_rarity {
                config.weight_exit_rarity = v;
            }
            if let Some(v) = fitness.weight_sanitizer {
                config.weight_sanitizer = v;
            }
            if let Some(v) = fitness.weight_stderr_novelty {
                config.weight_stderr_novelty = v;
            }
            if let Some(v) = fitness.weight_entropy {
                config.weight_entropy = v;
            }
            if let Some(v) = fitness.weight_fd_leak {
                config.weight_fd_leak = v;
            }
            if let Some(v) = fitness.weight_coverage {
                config.weight_coverage = v;
            }
            if let Some(v) = fitness.weight_verbose_anomaly {
                config.weight_verbose_anomaly = v;
            }
            if let Some(v) = fitness.weight_timing_breakdown {
                config.weight_timing_breakdown = v;
            }
            if let Some(v) = fitness.weight_size_ratio {
                config.weight_size_ratio = v;
            }
            if let Some(v) = fitness.weight_redirect {
                config.weight_redirect = v;
            }
            if let Some(v) = fitness.weight_nondeterminism {
                config.weight_nondeterminism = v;
            }
        }

        // Apply Servers overrides
        if let Some(servers) = parsed.servers {
            if let Some(v) = servers.start_servers {
                config.start_servers = v;
            }
            if let Some(ref mode_str) = servers.server_mode {
                config.server_mode = mode_str.parse::<ServerMode>()
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
            }
        }

        // Apply Protocols overrides
        if let Some(protocols) = parsed.protocols {
            if let Some(v) = protocols.enabled {
                config.enabled_protocols = v;
            }
            if let Some(v) = protocols.blocking_timeout_s {
                config.blocking_timeout_s = v;
            }
        }

        // Apply Output overrides
        if let Some(output) = parsed.output {
            if let Some(v) = output.database_path {
                config.database_path = v;
            }
            if let Some(v) = output.findings_dir {
                config.findings_dir = v;
            }
            if let Some(v) = output.fitness_threshold {
                config.fitness_threshold = v;
            }
        }

        // Apply Coverage overrides
        if let Some(coverage) = parsed.coverage {
            if let Some(v) = coverage.enabled {
                config.coverage_enabled = v;
            }
            if let Some(v) = coverage.gcov_strip_count {
                config.gcov_strip_count = v;
            }
            if let Some(v) = coverage.gcov_source_root {
                config.gcov_source_root = v;
            }
        }

        Ok(config)
    }

    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::from_toml(&content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        let config = FuzzerConfig::default();

        // GA defaults
        assert_eq!(config.population_size, 50);
        assert_eq!(config.max_generations, 15);
        assert_eq!(config.mutation_rate, 0.02);
        assert_eq!(config.crossover_rate, 0.3);
        assert_eq!(config.elitism_percent, 0.1);
        assert_eq!(config.seed, None);

        // Curl defaults
        assert_eq!(config.curl_path, "curl");
        assert_eq!(config.timeout_ms, 3000);
        assert_eq!(config.target_url, "http://localhost:8080");
        assert_eq!(config.flags_overlay_path, "config/curl-flags.toml");
        assert_eq!(config.min_flags, 5);
        assert_eq!(config.max_flags, 30);
        assert_eq!(config.max_active_flags, 35);

        // Fitness defaults
        assert_eq!(config.weight_crash, 100.0);
        assert_eq!(config.weight_exit_code, 10.0);
        assert_eq!(config.weight_timing, 5.0);
        assert_eq!(config.weight_stderr, 3.0);
        assert_eq!(config.weight_http_anomaly, 2.0);
        assert_eq!(config.weight_memory, 4.0);
        assert_eq!(config.weight_cpu, 3.0);
        assert_eq!(config.weight_core_dump, 150.0);
        assert_eq!(config.weight_stderr_size, 2.0);
        assert_eq!(config.weight_stdout_size, 2.0);
        assert_eq!(config.weight_exit_rarity, 5.0);
        assert_eq!(config.weight_sanitizer, 200.0);
        assert_eq!(config.weight_stderr_novelty, 3.0);
        assert_eq!(config.weight_entropy, 3.0);
        assert_eq!(config.weight_fd_leak, 5.0);
        assert_eq!(config.weight_coverage, 10.0);
        assert_eq!(config.weight_verbose_anomaly, 4.0);
        assert_eq!(config.weight_timing_breakdown, 6.0);
        assert_eq!(config.weight_size_ratio, 4.0);
        assert_eq!(config.weight_redirect, 5.0);
        assert_eq!(config.weight_nondeterminism, 20.0);

        // Protocol defaults
        assert_eq!(config.enabled_protocols, vec!["http", "https", "ftp", "smtp", "imap"]);
        assert_eq!(config.blocking_timeout_s, 5);
        assert!(config.protocol_port_overrides.is_empty());
        assert!(config.single_protocol.is_none());
        assert!(config.multi_protocols.is_none());
        assert_eq!(config.weight_diversity, 1.0);

        // Servers defaults
        assert_eq!(config.start_servers, true);

        // Output defaults
        assert_eq!(config.database_path, "curl-fuzzer.db");
        assert_eq!(config.findings_dir, "curl-findings");
        assert_eq!(config.fitness_threshold, 25.0);

        // Coverage defaults
        assert_eq!(config.coverage_enabled, true);
        assert_eq!(config.gcov_strip_count, 5);
        assert_eq!(config.gcov_source_root, "/home/jfuller/src/curl");
    }

    #[test]
    fn test_parse_toml_with_overrides() {
        let toml_str = r#"
            [ga]
            population_size = 100
            max_generations = 200
            mutation_rate = 0.1
            seed = 42

            [curl]
            curl_path = "/usr/bin/curl"
            target_url = "http://example.com"
            min_flags = 10

            [fitness]
            weight_crash = 150.0
            weight_timing = 10.0

            [servers]
            start_servers = false

            [protocols]
            enabled = ["http", "ftp"]
            blocking_timeout_s = 10

            [output]
            database_path = "custom.db"
            fitness_threshold = 10.0
        "#;

        let config = FuzzerConfig::from_toml(toml_str).unwrap();

        // Check overridden values
        assert_eq!(config.population_size, 100);
        assert_eq!(config.max_generations, 200);
        assert_eq!(config.mutation_rate, 0.1);
        assert_eq!(config.seed, Some(42));

        assert_eq!(config.curl_path, "/usr/bin/curl");
        assert_eq!(config.target_url, "http://example.com");
        assert_eq!(config.min_flags, 10);

        assert_eq!(config.weight_crash, 150.0);
        assert_eq!(config.weight_timing, 10.0);

        assert_eq!(config.start_servers, false);
        assert_eq!(config.enabled_protocols, vec!["http", "ftp"]);
        assert_eq!(config.blocking_timeout_s, 10);

        assert_eq!(config.database_path, "custom.db");
        assert_eq!(config.fitness_threshold, 10.0);

        // Check non-overridden defaults are preserved
        assert_eq!(config.crossover_rate, 0.3);
        assert_eq!(config.timeout_ms, 3000);
        assert_eq!(config.weight_exit_code, 10.0);
    }

    #[test]
    fn test_parse_protocol_config() {
        let toml_str = r#"
            [protocols]
            enabled = ["http", "ftp", "mqtt"]
            blocking_timeout_s = 3
        "#;
        let config = FuzzerConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.enabled_protocols, vec!["http", "ftp", "mqtt"]);
        assert_eq!(config.blocking_timeout_s, 3);
    }

    #[test]
    fn test_default_protocol_config() {
        let config = FuzzerConfig::default();
        assert_eq!(config.enabled_protocols, vec!["http", "https", "ftp", "smtp", "imap"]);
        assert_eq!(config.blocking_timeout_s, 5);
        assert!(config.protocol_port_overrides.is_empty());
        assert!(config.single_protocol.is_none());
        assert!(config.multi_protocols.is_none());
    }

    #[test]
    fn test_server_mode_default_is_both() {
        let cfg = FuzzerConfig::default();
        assert_eq!(cfg.server_mode, ServerMode::Both);
    }

    #[test]
    fn test_server_mode_from_str() {
        assert_eq!("good".parse::<ServerMode>().unwrap(), ServerMode::Good);
        assert_eq!("evil".parse::<ServerMode>().unwrap(), ServerMode::Evil);
        assert_eq!("both".parse::<ServerMode>().unwrap(), ServerMode::Both);
        assert!("invalid".parse::<ServerMode>().is_err());
    }

    #[test]
    fn test_server_mode_from_toml() {
        let toml_str = r#"
            [servers]
            server_mode = "evil"
        "#;
        let cfg = FuzzerConfig::from_toml(toml_str).unwrap();
        assert_eq!(cfg.server_mode, ServerMode::Evil);
    }

    #[test]
    fn test_coverage_config_disabled_round_trip() {
        let toml_str = r#"
            [coverage]
            enabled = false
            gcov_strip_count = 3
            gcov_source_root = "/opt/curl-src"
        "#;
        let config = FuzzerConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.coverage_enabled, false);
        assert_eq!(config.gcov_strip_count, 3);
        assert_eq!(config.gcov_source_root, "/opt/curl-src");
    }
}
