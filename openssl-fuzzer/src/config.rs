use anyhow::Result;
use serde::Deserialize;
use std::fs;

#[derive(Debug, Clone)]
pub struct FuzzerConfig {
    // GA
    pub population_size: usize,
    pub max_generations: usize,
    pub mutation_rate: f64,
    pub crossover_rate: f64,
    pub elitism_percent: f64,
    pub seed: Option<u64>,

    // OpenSSL
    pub openssl_path: String,
    pub timeout_ms: u64,
    pub connect: String,
    pub flags_overlay_path: String,
    pub min_flags: usize,
    pub max_flags: usize,
    pub max_active_flags: usize,

    // Fitness
    pub weight_crash: f64,
    pub weight_sanitizer: f64,
    pub weight_exit_code: f64,
    pub weight_timing: f64,
    pub weight_tls_anomaly: f64,
    pub weight_memory: f64,

    // Output
    pub database_path: String,
    pub findings_dir: String,
    pub fitness_threshold: f64,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            population_size: 50,
            max_generations: 100,
            mutation_rate: 0.05,
            crossover_rate: 0.8,
            elitism_percent: 0.1,
            seed: None,

            openssl_path: "/home/jfuller/src/openssl/apps/openssl".to_string(),
            timeout_ms: 5000,
            connect: "localhost:8443".to_string(),
            flags_overlay_path: "config/openssl-flags.toml".to_string(),
            min_flags: 2,
            max_flags: 20,
            max_active_flags: 20,

            weight_crash: 100.0,
            weight_sanitizer: 200.0,
            weight_exit_code: 10.0,
            weight_timing: 5.0,
            weight_tls_anomaly: 15.0,
            weight_memory: 8.0,

            database_path: "openssl-fuzzer.db".to_string(),
            findings_dir: "openssl-findings".to_string(),
            fitness_threshold: 25.0,
        }
    }
}

#[derive(Debug, Deserialize)]
struct TomlConfig {
    ga: Option<GaSection>,
    openssl: Option<OpenSslSection>,
    fitness: Option<FitnessSection>,
    output: Option<OutputSection>,
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
struct OpenSslSection {
    openssl_path: Option<String>,
    timeout_ms: Option<u64>,
    connect: Option<String>,
    flags_overlay_path: Option<String>,
    min_flags: Option<usize>,
    max_flags: Option<usize>,
    max_active_flags: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FitnessSection {
    weight_crash: Option<f64>,
    weight_sanitizer: Option<f64>,
    weight_exit_code: Option<f64>,
    weight_timing: Option<f64>,
    weight_tls_anomaly: Option<f64>,
    weight_memory: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct OutputSection {
    database_path: Option<String>,
    findings_dir: Option<String>,
    fitness_threshold: Option<f64>,
}

impl FuzzerConfig {
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        let parsed: TomlConfig = toml::from_str(toml_str)?;
        let mut config = Self::default();

        if let Some(ga) = parsed.ga {
            if let Some(v) = ga.population_size { config.population_size = v; }
            if let Some(v) = ga.max_generations { config.max_generations = v; }
            if let Some(v) = ga.mutation_rate { config.mutation_rate = v; }
            if let Some(v) = ga.crossover_rate { config.crossover_rate = v; }
            if let Some(v) = ga.elitism_percent { config.elitism_percent = v; }
            if let Some(v) = ga.seed { config.seed = Some(v); }
        }

        if let Some(openssl) = parsed.openssl {
            if let Some(v) = openssl.openssl_path { config.openssl_path = v; }
            if let Some(v) = openssl.timeout_ms { config.timeout_ms = v; }
            if let Some(v) = openssl.connect { config.connect = v; }
            if let Some(v) = openssl.flags_overlay_path { config.flags_overlay_path = v; }
            if let Some(v) = openssl.min_flags { config.min_flags = v; }
            if let Some(v) = openssl.max_flags { config.max_flags = v; }
            if let Some(v) = openssl.max_active_flags { config.max_active_flags = v; }
        }

        if let Some(fitness) = parsed.fitness {
            if let Some(v) = fitness.weight_crash { config.weight_crash = v; }
            if let Some(v) = fitness.weight_sanitizer { config.weight_sanitizer = v; }
            if let Some(v) = fitness.weight_exit_code { config.weight_exit_code = v; }
            if let Some(v) = fitness.weight_timing { config.weight_timing = v; }
            if let Some(v) = fitness.weight_tls_anomaly { config.weight_tls_anomaly = v; }
            if let Some(v) = fitness.weight_memory { config.weight_memory = v; }
        }

        if let Some(output) = parsed.output {
            if let Some(v) = output.database_path { config.database_path = v; }
            if let Some(v) = output.findings_dir { config.findings_dir = v; }
            if let Some(v) = output.fitness_threshold { config.fitness_threshold = v; }
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
        assert_eq!(config.population_size, 50);
        assert_eq!(config.max_generations, 100);
        assert_eq!(config.connect, "localhost:8443");
        assert_eq!(config.weight_crash, 100.0);
        assert_eq!(config.weight_sanitizer, 200.0);
        assert_eq!(config.database_path, "openssl-fuzzer.db");
        assert_eq!(config.findings_dir, "openssl-findings");
    }

    #[test]
    fn test_parse_toml_overrides() {
        let toml_str = r#"
            [ga]
            population_size = 100
            seed = 42

            [openssl]
            connect = "localhost:9443"
            timeout_ms = 10000

            [fitness]
            weight_crash = 150.0

            [output]
            database_path = "custom.db"
        "#;

        let config = FuzzerConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.population_size, 100);
        assert_eq!(config.seed, Some(42));
        assert_eq!(config.connect, "localhost:9443");
        assert_eq!(config.timeout_ms, 10000);
        assert_eq!(config.weight_crash, 150.0);
        assert_eq!(config.database_path, "custom.db");
        // Non-overridden defaults preserved
        assert_eq!(config.mutation_rate, 0.05);
        assert_eq!(config.weight_sanitizer, 200.0);
    }
}
