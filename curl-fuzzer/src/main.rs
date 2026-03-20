mod dictionaries;
mod flag_def;
mod flag_parser;
mod flag_overlay;
mod flag_seeds;
mod individual;
mod executor;
mod fitness;
mod persistence;
mod findings;
mod config;
mod servers;
mod coverage;
mod verbose_state;

use curl_fuzzer::protocol;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::FuzzerConfig;

#[derive(Parser)]
#[command(name = "curl-fuzzer")]
#[command(about = "Genetic algorithm fuzzer for curl", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the fuzzer
    Run {
        /// Path to curl binary
        #[arg(long)]
        curl_path: Option<String>,

        /// Path to config file
        #[arg(long)]
        config: Option<String>,

        /// Population size
        #[arg(long)]
        population_size: Option<usize>,

        /// Number of generations
        #[arg(long)]
        generations: Option<usize>,

        /// Mutation rate
        #[arg(long)]
        mutation_rate: Option<f64>,

        /// Target URL
        #[arg(long)]
        target_url: Option<String>,

        /// Per-curl timeout in milliseconds
        #[arg(long)]
        timeout_ms: Option<u64>,

        /// Don't start test servers
        #[arg(long)]
        no_servers: bool,

        /// Server response mode: good (normal), evil (malformed), or both (alternating)
        #[arg(long, default_value = "both")]
        server_mode: String,

        /// Output directory
        #[arg(long)]
        output_dir: Option<String>,

        /// Crossover rate
        #[arg(long)]
        crossover_rate: Option<f64>,

        /// Maximum active flags per curl invocation
        #[arg(long)]
        max_active_flags: Option<usize>,

        /// Single protocol mode
        #[arg(long)]
        protocol: Option<String>,

        /// Multi-protocol mode (comma-separated)
        #[arg(long, value_delimiter = ',')]
        protocols: Option<Vec<String>>,

        /// Seed population from a previous run's database (loads top N findings)
        #[arg(long)]
        seed_db: Option<String>,

        /// Number of seeds to load from seed database (default: 50% of population)
        #[arg(long)]
        seed_count: Option<usize>,

        /// Additional dictionary files (AFL++ .dict or plain text, can be repeated)
        #[arg(long = "dict", value_name = "FILE")]
        dict_files: Vec<String>,

        /// Exclude specific flags from fuzzing (can be repeated, e.g. --exclude-flag --doh-url)
        #[arg(long = "exclude-flag", value_name = "FLAG")]
        exclude_flags: Vec<String>,

        /// Always include specific flags in every individual (can be repeated, e.g. --include-flag --verbose)
        #[arg(long = "include-flag", value_name = "FLAG")]
        include_flags: Vec<String>,

        /// Disable coverage-guided fitness (no gcov instrumentation)
        #[arg(long)]
        no_coverage: bool,

        /// Path to curl source root for gcov (overrides config)
        #[arg(long)]
        gcov_source_root: Option<String>,
    },
    /// Replay a specific finding
    Replay {
        /// Finding ID to replay
        id: String,
    },
    /// Generate a report of findings
    Report {
        /// Number of top findings to show
        #[arg(long, default_value = "10")]
        top: usize,
    },
    /// Start test servers and keep them running
    Servers {
        /// Protocols to start (comma-separated)
        #[arg(long, value_delimiter = ',')]
        protocols: Option<Vec<String>>,

        /// Path to config file
        #[arg(long)]
        config: Option<String>,

        /// Server response mode: good (normal), evil (malformed), or both (alternating)
        #[arg(long, default_value = "both")]
        server_mode: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            curl_path,
            config,
            population_size,
            generations,
            mutation_rate,
            target_url,
            timeout_ms,
            no_servers,
            server_mode,
            output_dir,
            crossover_rate,
            max_active_flags,
            protocol,
            protocols,
            seed_db,
            seed_count,
            dict_files,
            exclude_flags,
            include_flags,
            no_coverage,
            gcov_source_root,
        } => {
            // Load config from file or use defaults
            let mut cfg = if let Some(config_path) = config {
                FuzzerConfig::load(&config_path)?
            } else {
                FuzzerConfig::default()
            };

            // Apply CLI overrides
            if let Some(path) = curl_path {
                cfg.curl_path = path;
            }
            if let Some(size) = population_size {
                cfg.population_size = size;
            }
            if let Some(gens) = generations {
                cfg.max_generations = gens;
            }
            if let Some(rate) = mutation_rate {
                cfg.mutation_rate = rate;
            }
            if let Some(url) = target_url {
                cfg.target_url = url;
            }
            if let Some(v) = timeout_ms {
                cfg.timeout_ms = v;
            }
            if let Some(rate) = crossover_rate {
                cfg.crossover_rate = rate;
            }
            if no_servers {
                cfg.start_servers = false;
            }
            if no_coverage {
                cfg.coverage_enabled = false;
            }
            if let Some(root) = gcov_source_root {
                cfg.gcov_source_root = root;
            }
            if let Ok(mode) = server_mode.parse::<config::ServerMode>() {
                cfg.server_mode = mode;
            } else {
                anyhow::bail!("Invalid --server-mode '{}'. Must be 'good', 'evil', or 'both'.", server_mode);
            }
            if let Some(dir) = output_dir {
                cfg.findings_dir = dir;
            }
            if let Some(v) = max_active_flags {
                cfg.max_active_flags = v;
            }

            if protocol.is_some() && protocols.is_some() {
                return Err(anyhow::anyhow!("--protocol and --protocols are mutually exclusive"));
            }

            // Apply protocol CLI overrides
            if let Some(ref p) = protocol {
                cfg.single_protocol = Some(p.clone());
            }
            if let Some(ref ps) = protocols {
                cfg.multi_protocols = Some(ps.clone());
            }

            run_fuzzer(cfg, seed_db, seed_count, dict_files, exclude_flags, include_flags)?;
        }
        Commands::Replay { id } => {
            use std::fs;
            use std::path::Path;
            use persistence::FuzzDatabase;

            // Check if id is a file path
            if Path::new(&id).exists() {
                // It's a file, just print its contents
                let contents = fs::read_to_string(&id)?;
                println!("{}", contents);
            } else {
                // Try to parse as a numeric rowid
                match id.parse::<i64>() {
                    Ok(_rowid) => {
                        // Query database
                        let db = FuzzDatabase::open("curl-fuzzer.db")?;
                        let conn = &db;

                        // For simplicity, just query all and filter
                        let _findings = conn.get_top_findings(1000)?;

                        // Note: SQLite rowid is implicit, we'd need custom query
                        // For now, just print error message
                        println!("Database replay by rowid not fully implemented");
                        println!("Use a file path instead, or check findings directory");
                    }
                    Err(_) => {
                        println!("Error: '{}' is not a valid file path or numeric ID", id);
                    }
                }
            }
        }
        Commands::Report { top } => {
            use persistence::FuzzDatabase;

            let db = FuzzDatabase::open("curl-fuzzer.db")?;
            let findings = db.get_top_findings(top)?;

            if findings.is_empty() {
                println!("No findings in database");
            } else {
                println!("\n=== Top {} Findings ===\n", top);
                println!("{:<5} {:<8} {:<10} {:<10} {:<20} {}", "Gen", "Ind", "Fitness", "Exit", "Time", "Command");
                println!("{:-<120}", "");

                for finding in findings {
                    let cmd_preview = if finding.curl_command.len() > 50 {
                        format!("{}...", &finding.curl_command[..47])
                    } else {
                        finding.curl_command.clone()
                    };

                    let timestamp = finding.created_at.as_deref().unwrap_or("-");

                    println!(
                        "{:<5} {:<8} {:<10.2} {:<10} {:<20} {}",
                        finding.generation,
                        finding.individual_id,
                        finding.fitness_total,
                        finding.exit_code,
                        timestamp,
                        cmd_preview
                    );
                }

                println!();
            }
        }
        Commands::Servers { protocols, config, server_mode } => {
            use servers::ServerManager;
            use protocol::ProtocolRegistry;

            let cfg = if let Some(config_path) = config {
                FuzzerConfig::load(&config_path)?
            } else {
                FuzzerConfig::default()
            };

            let server_mode: config::ServerMode = server_mode.parse()
                .map_err(|e: String| anyhow::anyhow!("{}", e))?;

            let registry = ProtocolRegistry::default();
            let enabled = protocols.unwrap_or_else(|| cfg.enabled_protocols.clone());

            let mut manager = ServerManager::new();

            // Generate certs for TLS protocols
            let has_tls = enabled.iter().any(|p| registry.is_tls_protocol(p));
            if has_tls {
                match manager.generate_certs() {
                    Ok(()) => println!("TLS certificates generated"),
                    Err(e) => eprintln!("Warning: Failed to generate certs: {}", e),
                }
            }

            // Create fixtures if file:// is enabled
            if enabled.contains(&"file".to_string()) {
                let _ = manager.create_fixtures();
            }

            let spawn_list = registry.server_spawn_list(&enabled, &cfg.protocol_port_overrides);
            let failed = manager.start_protocols(&spawn_list, &server_mode.to_string())?;

            println!("\nTest servers:");
            for entry in &spawn_list {
                let status = if failed.contains(&entry.port) { " (FAILED)" } else { "" };
                let tls_label = if entry.tls { " (TLS)" } else { "" };
                println!("  {}:{}{}{}", entry.script, entry.port, tls_label, status);
            }
            println!("\nPress Ctrl+C to stop.");

            let (tx, rx) = std::sync::mpsc::channel();
            ctrlc::set_handler(move || { let _ = tx.send(()); })
                .expect("Error setting Ctrl+C handler");
            let _ = rx.recv();

            println!("\nStopping servers...");
            manager.stop();
        }
    }

    Ok(())
}

fn run_fuzzer(cfg: FuzzerConfig, seed_db: Option<String>, seed_count: Option<usize>, dict_files: Vec<String>, exclude_flags: Vec<String>, include_flags: Vec<String>) -> Result<()> {
    use flag_parser::discover_flags;
    use flag_overlay::{load_overlay, apply_overlay};
    use individual::{CurlIndividual, CurlCrossover, CurlMutation};
    use fitness::CurlFitnessEvaluator;
    use servers::ServerManager;
    use persistence::{FuzzDatabase, RunRecord};
    use findings::write_finding;
    use ga_engine::adaptive::{AdaptiveMutationConfig, DiversityConfig};
    use ga_engine::engine::{EngineConfig, EvolutionEngine};
    use ga_engine::selection::TournamentSelection;
    use ga_engine::crossover::UniformCrossover;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    println!("Starting curl fuzzer...");
    println!("Configuration:");
    println!("  Population size: {}", cfg.population_size);
    println!("  Max generations: {}", cfg.max_generations);
    println!("  Mutation rate: {}", cfg.mutation_rate);
    println!("  Target URL: {}", cfg.target_url);
    println!("  Database: {}", cfg.database_path);
    println!("  Findings dir: {}", cfg.findings_dir);
    println!("  Max active flags: {}", cfg.max_active_flags);
    println!();

    // 1. Discover curl flags
    println!("Discovering curl flags from '{}'...", cfg.curl_path);
    let mut discovered_flags = discover_flags(&cfg.curl_path)?;
    println!("  Discovered {} flags", discovered_flags.len());

    // 2. Apply overlay if file exists
    println!("Loading flag overlay from '{}'...", cfg.flags_overlay_path);
    let overlay = load_overlay(&cfg.flags_overlay_path)?;
    println!("  Overlay contains {} rules", overlay.len());

    apply_overlay(&mut discovered_flags, &overlay);

    // 2b. Build dictionary (embedded core + external files)
    let mut dict = dictionaries::Dictionary::embedded();
    let embedded_count = dict.strings.len() + dict.headers.len() + dict.urls.len()
        + dict.data.len() + dict.commands.len();
    println!("  Loaded {} embedded dictionary entries", embedded_count);

    for dict_path in &dict_files {
        match dict.load_file(dict_path) {
            Ok(count) => println!("  Loaded {} entries from '{}'", count, dict_path),
            Err(e) => eprintln!("  Warning: {}", e),
        }
    }

    // 2c. Auto-enrich remaining String flags with seed values + dictionary
    let string_before = discovered_flags.iter()
        .filter(|f| matches!(f.flag_type, flag_def::FlagType::String))
        .count();
    flag_seeds::enrich_flags(&mut discovered_flags, Some(&dict));
    let string_after = discovered_flags.iter()
        .filter(|f| matches!(f.flag_type, flag_def::FlagType::String))
        .count();
    println!("  Enriched {} flags with seed values ({} still untyped)",
        string_before - string_after, string_after);

    // 2d. Apply CLI --exclude-flag filters
    if !exclude_flags.is_empty() {
        let before = discovered_flags.len();
        discovered_flags.retain(|f| {
            !exclude_flags.iter().any(|ex| {
                let normalized = if ex.starts_with("--") { ex.clone() } else { format!("--{}", ex) };
                f.name == normalized
            })
        });
        println!("  Excluded {} flags via --exclude-flag: {:?}", before - discovered_flags.len(), exclude_flags);
    }

    // 2e. Normalize --include-flag names and validate they exist
    let include_flag_set: std::collections::HashSet<String> = include_flags.iter().map(|f| {
        if f.starts_with("--") { f.clone() } else { format!("--{}", f) }
    }).collect();
    if !include_flag_set.is_empty() {
        let flag_names: std::collections::HashSet<&str> = discovered_flags.iter().map(|f| f.name.as_str()).collect();
        for f in &include_flag_set {
            if !flag_names.contains(f.as_str()) {
                eprintln!("  Warning: --include-flag '{}' not found in discovered flags, ignoring", f);
            }
        }
        let valid_count = include_flag_set.iter().filter(|f| flag_names.contains(f.as_str())).count();
        println!("  Always including {} flags via --include-flag: {:?}", valid_count, include_flags);
    }

    println!("  Final flag set: {} flags", discovered_flags.len());
    println!();

    // 3. Set up protocol registry and start servers
    use protocol::ProtocolRegistry;
    use flag_overlay::parse_flag_affinity;

    let registry = ProtocolRegistry::default();

    // Determine enabled protocols and mode
    let (enabled_protocols, protocol_mode) = if let Some(ref single) = cfg.single_protocol {
        (vec![single.clone()], individual::ProtocolMode::Fixed(single.clone()))
    } else if let Some(ref multi) = cfg.multi_protocols {
        let first = multi.first().cloned().unwrap_or("http".into());
        (multi.clone(), individual::ProtocolMode::Evolvable(first))
    } else {
        let first = cfg.enabled_protocols.first().cloned().unwrap_or("http".into());
        if cfg.enabled_protocols.len() == 1 {
            (cfg.enabled_protocols.clone(), individual::ProtocolMode::Fixed(first))
        } else {
            (cfg.enabled_protocols.clone(), individual::ProtocolMode::Evolvable(first))
        }
    };

    println!("  Enabled protocols: {:?}", enabled_protocols);
    println!("  Server mode: {}", cfg.server_mode);

    let mut server_manager = ServerManager::new();
    if cfg.start_servers {
        println!("Starting test servers...");

        // Generate TLS certs
        match server_manager.generate_certs() {
            Ok(()) => println!("  TLS certificates generated"),
            Err(e) => println!("  Warning: Failed to generate certs: {}", e),
        }

        // Create file:// fixtures
        match server_manager.create_fixtures() {
            Ok(()) => println!("  File fixtures created"),
            Err(e) => println!("  Warning: Failed to create fixtures: {}", e),
        }

        // Build spawn list and start servers
        let spawn_list = registry.server_spawn_list(&enabled_protocols, &cfg.protocol_port_overrides);
        println!("  Starting {} server processes...", spawn_list.len());

        match server_manager.start_protocols(&spawn_list, &cfg.server_mode.to_string()) {
            Ok(failed) => {
                if failed.is_empty() {
                    println!("  All servers started successfully");
                } else {
                    println!("  Some servers failed on ports: {:?}", failed);
                }
            }
            Err(e) => {
                println!("  Warning: Failed to start servers: {}", e);
                println!("  Continuing without servers...");
            }
        }
        println!();
    }

    // 4. Open SQLite database
    println!("Opening database '{}'...", cfg.database_path);
    let db = FuzzDatabase::open(&cfg.database_path)?;
    println!("  Database ready");
    println!();

    // 5. Create initial population
    println!("Creating initial population...");
    let mut rng = match cfg.seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_entropy(),
    };

    let mut population = Vec::new();

    // Seed from previous database if provided
    if let Some(ref db_path) = seed_db {
        let max_seeds = seed_count.unwrap_or(cfg.population_size / 2);
        match FuzzDatabase::open(db_path) {
            Ok(seed_db) => {
                let findings = seed_db.get_top_findings(max_seeds)?;
                println!("  Loading {} seeds from '{}'", findings.len(), db_path);
                for finding in &findings {
                    let individual = CurlIndividual::from_command_str(
                        &finding.curl_command,
                        &discovered_flags,
                        protocol_mode.clone(),
                    );
                    population.push(individual);
                }
                println!("  Seeded {} individuals from previous run", population.len());
            }
            Err(e) => {
                println!("  Warning: Could not open seed database '{}': {}", db_path, e);
            }
        }
    }

    // Fill remaining slots with random individuals
    let remaining = cfg.population_size.saturating_sub(population.len());
    for _ in 0..remaining {
        let individual = CurlIndividual::random(
            &discovered_flags,
            cfg.min_flags,
            cfg.max_flags,
            &mut rng,
            protocol_mode.clone(),
            &include_flag_set,
        );
        population.push(individual);
    }
    println!("  Population: {} seeded + {} random = {} total",
        population.len() - remaining, remaining, population.len());
    println!();

    // 6. Set up GA components
    let engine_config = EngineConfig {
        population_size: cfg.population_size,
        max_generations: cfg.max_generations,
        mutation_rate: cfg.mutation_rate,
        crossover_rate: cfg.crossover_rate,
        elitism_count: (cfg.population_size as f64 * cfg.elitism_percent) as usize,
        seed: cfg.seed,
    };

    let tournament_selection = TournamentSelection::new(3);
    let uniform_crossover = CurlCrossover::new(UniformCrossover::new());

    // Load flag affinity
    let flag_affinity = match std::fs::read_to_string(&cfg.flags_overlay_path) {
        Ok(content) => parse_flag_affinity(&content).unwrap_or_default(),
        Err(_) => std::collections::HashMap::new(),
    };

    let curl_mutation = CurlMutation::new(
        cfg.mutation_rate,
        discovered_flags.clone(),
        cfg.max_active_flags,
        flag_affinity,
        enabled_protocols.clone(),
        include_flag_set,
    );

    // 7. Create fitness evaluator
    let mut evaluator = CurlFitnessEvaluator::new(
        cfg.curl_path.clone(),
        cfg.target_url.clone(),
        cfg.timeout_ms,
        fitness::CurlFitnessScorer {
            crash_weight: cfg.weight_crash,
            exit_code_weight: cfg.weight_exit_code,
            timing_weight: cfg.weight_timing,
            stderr_weight: cfg.weight_stderr,
            http_anomaly_weight: cfg.weight_http_anomaly,
            memory_weight: cfg.weight_memory,
            cpu_weight: cfg.weight_cpu,
            core_dump_weight: cfg.weight_core_dump,
            stderr_size_weight: cfg.weight_stderr_size,
            stdout_size_weight: cfg.weight_stdout_size,
            exit_rarity_weight: cfg.weight_exit_rarity,
            sanitizer_weight: cfg.weight_sanitizer,
            stderr_novelty_weight: cfg.weight_stderr_novelty,
            entropy_weight: cfg.weight_entropy,
            fd_leak_weight: cfg.weight_fd_leak,
            coverage_weight: cfg.weight_coverage,
            verbose_anomaly_weight: cfg.weight_verbose_anomaly,
            timing_breakdown_weight: cfg.weight_timing_breakdown,
            size_ratio_weight: cfg.weight_size_ratio,
            redirect_weight: cfg.weight_redirect,
            nondeterminism_weight: cfg.weight_nondeterminism,
        },
    );
    evaluator.blocking_timeout_s = cfg.blocking_timeout_s;
    evaluator.cert_path = server_manager.cert_path.as_ref().map(|p| p.to_string_lossy().to_string());
    evaluator.port_overrides = cfg.protocol_port_overrides.clone();
    evaluator.state_dir = Some(server_manager.state_dir.to_string_lossy().to_string());
    evaluator.coverage_enabled = cfg.coverage_enabled;
    evaluator.gcov_source_root = cfg.gcov_source_root.clone();
    evaluator.gcov_strip_count = cfg.gcov_strip_count;

    // 8. Run the evolution engine with per-generation progress
    println!("Starting evolution...\n");
    let engine = EvolutionEngine::new(engine_config);

    let curl_path = cfg.curl_path.clone();
    let target_url = cfg.target_url.clone();
    let findings_dir = cfg.findings_dir.clone();
    let fitness_threshold = cfg.fitness_threshold;
    let max_gens = cfg.max_generations;

    let mut total_findings = 0usize;
    let mut best_fitness = 0.0f64;
    let start_time = std::time::Instant::now();

    let adaptive_config = AdaptiveMutationConfig {
        base_rate: cfg.mutation_rate,
        max_rate: cfg.mutation_rate * 5.0,
        stagnation_window: 20,
        spike_duration: 3,
    };

    let diversity_config = DiversityConfig::default();

    let result = engine.run_adaptive(
        population,
        &evaluator,
        &tournament_selection,
        &uniform_crossover,
        &curl_mutation,
        adaptive_config,
        diversity_config,
        |gen, scored, is_spiking, current_rate, diversity| {
            let best = &scored[0];
            let worst = &scored[scored.len() - 1];
            let avg: f64 = scored.iter().map(|s| s.fitness.total).sum::<f64>() / scored.len() as f64;
            let elapsed = start_time.elapsed().as_secs();

            if best.fitness.total > best_fitness {
                best_fitness = best.fitness.total;
            }

            // Progress line
            let spike_indicator = if is_spiking { " SPIKE" } else { "" };
            print!("\rGen {}/{}: best={:.1} avg={:.1} worst={:.1} | findings={} div={:.0}% rate={:.3}{} elapsed={}s",
                gen + 1, max_gens,
                best.fitness.total, avg, worst.fitness.total,
                total_findings, diversity * 100.0, current_rate, spike_indicator, elapsed,
            );
            use std::io::Write;
            let _ = std::io::stdout().flush();

            // Persist best individual from this generation
            let individual = &best.individual;
            let fitness = &best.fitness;

            let proto_name = individual.protocol_name();
            let proto_def = registry.get(proto_name);
            let target_url_for_cmd = match proto_def {
                Some(p) => {
                    let port = cfg.protocol_port_overrides.get(proto_name).copied()
                        .unwrap_or(p.default_port);
                    registry.url_for(proto_name, port)
                }
                None => target_url.clone(),
            };
            let curl_command = individual.to_command_string(&curl_path, &target_url_for_cmd);
            let components_json = serde_json::to_string(&fitness.components).unwrap_or_default();

            let run_record = RunRecord {
                generation: gen,
                individual_id: 0,
                curl_command: curl_command.clone(),
                fitness_total: fitness.total,
                fitness_components: components_json,
                exit_code: 0,
                signal: None,
                duration_ms: 0,
                stdout: String::new(),
                stderr: String::new(),
                protocol: individual.protocol_name().to_string(),
                created_at: None,
            };

            let _ = db.insert_run(&run_record);

            // Write finding if above threshold
            if fitness.total >= fitness_threshold {
                let malformation_note = fitness.metadata.get("server_malformation")
                    .map(|m| format!("\nServer malformation: {}", m))
                    .unwrap_or_default();
                if let Ok(filename) = write_finding(
                    &findings_dir, gen, 0, &curl_command,
                    fitness.total, 0, None,
                    &format!("Fitness components: {:?}{}", fitness.components, malformation_note),
                ) {
                    total_findings += 1;
                    println!("\n  Finding: {:.2} -> {}", fitness.total, filename);
                }
            }

            true // continue
        },
    );

    // 9. Print summary
    println!("\n\n=== Fuzzing Complete ===");
    println!("Generations run: {}", result.generations_run);
    println!("Best fitness achieved: {:.2}", best_fitness);
    println!("Total findings (>= {:.2}): {}", fitness_threshold, total_findings);
    println!("Database: {}", cfg.database_path);
    println!("Findings directory: {}", cfg.findings_dir);

    // Servers will be stopped automatically via Drop

    Ok(())
}
