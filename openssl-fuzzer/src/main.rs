mod config;
mod dictionaries;
mod executor;
mod findings;
mod fitness;
mod flag_def;
mod flag_overlay;
mod flag_parser;
mod flag_seeds;
mod individual;
mod persistence;
mod subcommand;
mod tls_state;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "openssl-fuzzer")]
#[command(about = "Genetic algorithm fuzzer for openssl s_client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the fuzzer
    Run {
        /// Path to openssl binary
        #[arg(long, default_value = "/home/jfuller/src/openssl/apps/openssl")]
        openssl_path: String,

        /// Target host:port to connect to
        #[arg(long, default_value = "localhost:8443")]
        connect: String,

        /// Config TOML file
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

        /// Crossover rate
        #[arg(long)]
        crossover_rate: Option<f64>,

        /// Max active flags per individual
        #[arg(long)]
        max_active_flags: Option<usize>,

        /// Per-execution timeout in ms
        #[arg(long)]
        timeout_ms: Option<u64>,

        /// Random seed
        #[arg(long)]
        seed: Option<u64>,

        /// Database path
        #[arg(long)]
        database_path: Option<String>,

        /// Findings output directory
        #[arg(long)]
        findings_dir: Option<String>,

        /// Fitness threshold for saving findings
        #[arg(long)]
        fitness_threshold: Option<f64>,

        /// Additional dictionary files (AFL++ .dict or plain text, can be repeated)
        #[arg(long = "dict", value_name = "FILE")]
        dict_files: Vec<String>,

        /// Server mode: good, evil, or both
        #[arg(long, default_value = "good")]
        server_mode: String,

        /// Don't start the built-in TLS server
        #[arg(long)]
        no_servers: bool,

        /// OpenSSL subcommand to fuzz (s_client, x509, asn1parse, verify, req, enc)
        #[arg(long, default_value = "s_client")]
        subcommand: String,
    },
    /// Generate a report of findings
    Report {
        /// Number of top findings to show
        #[arg(long, default_value = "10")]
        top: usize,

        /// Database path
        #[arg(long, default_value = "openssl-fuzzer.db")]
        database_path: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            openssl_path,
            connect,
            config: config_path,
            population_size,
            generations,
            mutation_rate,
            crossover_rate,
            max_active_flags,
            timeout_ms,
            seed,
            database_path,
            findings_dir,
            fitness_threshold,
            dict_files,
            server_mode,
            no_servers,
            subcommand: subcmd_name,
        } => {
            // Load config from TOML if provided, otherwise use defaults
            let mut cfg = match config_path {
                Some(ref path) => config::FuzzerConfig::load(path)?,
                None => config::FuzzerConfig::default(),
            };

            // CLI overrides
            cfg.openssl_path = openssl_path;
            cfg.connect = connect;
            if let Some(v) = population_size { cfg.population_size = v; }
            if let Some(v) = generations { cfg.max_generations = v; }
            if let Some(v) = mutation_rate { cfg.mutation_rate = v; }
            if let Some(v) = crossover_rate { cfg.crossover_rate = v; }
            if let Some(v) = max_active_flags { cfg.max_active_flags = v; }
            if let Some(v) = timeout_ms { cfg.timeout_ms = v; }
            if let Some(v) = seed { cfg.seed = Some(v); }
            if let Some(v) = database_path { cfg.database_path = v; }
            if let Some(v) = findings_dir { cfg.findings_dir = v; }
            if let Some(v) = fitness_threshold { cfg.fitness_threshold = v; }

            // Resolve subcommand definition
            let subcmd_def = if subcmd_name == "s_client" {
                subcommand::SubCommandDef::s_client(&cfg.connect)
            } else {
                subcommand::SubCommandDef::from_name(&subcmd_name)
                    .ok_or_else(|| anyhow::anyhow!(
                        "Unknown subcommand '{}'. Available: {:?}",
                        subcmd_name, subcommand::SubCommandDef::available()
                    ))?
            };

            run_fuzzer(cfg, dict_files, server_mode, no_servers, subcmd_def)?;
        }
        Commands::Report { top, database_path } => {
            report_findings(top, &database_path)?;
        }
    }

    Ok(())
}

fn report_findings(top: usize, database_path: &str) -> Result<()> {
    let db = persistence::FuzzDatabase::open(database_path)?;
    let findings = db.get_top_findings(top)?;

    if findings.is_empty() {
        println!("No findings in database ({})", database_path);
    } else {
        println!("\n=== Top {} openssl-fuzzer Findings ===\n", top);
        println!("{:<5} {:<6} {:<10} {:<6} {:<8} {:<20} {}", "Gen", "Ind", "Fitness", "Exit", "Time", "When", "Command");
        println!("{:-<120}", "");

        for finding in &findings {
            let cmd_preview = if finding.openssl_command.len() > 45 {
                format!("{}...", &finding.openssl_command[..42])
            } else {
                finding.openssl_command.clone()
            };

            let signal_str = finding.signal
                .map(|s| format!(" (sig {})", s))
                .unwrap_or_default();

            let timestamp = finding.created_at.as_deref().unwrap_or("-");

            println!(
                "{:<5} {:<6} {:<10.2} {:<6}{} {:<8}ms {:<20} {}",
                finding.generation,
                finding.individual_id,
                finding.fitness_total,
                finding.exit_code,
                signal_str,
                finding.duration_ms,
                timestamp,
                cmd_preview,
            );
        }

        // Show fitness component breakdown for the top finding
        if let Some(best) = findings.first() {
            if !best.fitness_components.is_empty() && best.fitness_components != "{}" {
                println!("\nTop finding breakdown:");
                if let Ok(components) = serde_json::from_str::<serde_json::Value>(&best.fitness_components) {
                    if let Some(obj) = components.as_object() {
                        for (k, v) in obj {
                            println!("  {}: {:.1}", k, v.as_f64().unwrap_or(0.0));
                        }
                    }
                }
            }
        }

        println!();
    }

    Ok(())
}

fn run_fuzzer(
    cfg: config::FuzzerConfig,
    dict_files: Vec<String>,
    server_mode: String,
    no_servers: bool,
    subcmd_def: subcommand::SubCommandDef,
) -> Result<()> {
    use individual::{OpenSslIndividual, OpenSslCrossover, OpenSslMutation};
    use fitness::{OpenSslFitnessEvaluator, OpenSslFitnessScorer};
    use persistence::{FuzzDatabase, RunRecord};
    use findings::write_finding;
    use ga_engine::adaptive::{AdaptiveMutationConfig, DiversityConfig};
    use ga_engine::engine::{EngineConfig, EvolutionEngine};
    use ga_engine::selection::TournamentSelection;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let is_s_client = subcmd_def.kind == subcommand::SubCommandKind::SClient;

    // Validate server mode (only relevant for s_client)
    if is_s_client && !["good", "evil", "both"].contains(&server_mode.as_str()) {
        return Err(anyhow::anyhow!("Invalid --server-mode '{}'. Must be 'good', 'evil', or 'both'.", server_mode));
    }

    // Discover flags for the target subcommand
    println!("Discovering openssl {} flags...", subcmd_def.name);
    let excluded: Vec<&str> = subcmd_def.excluded_flags.clone();
    let mut flag_defs = flag_parser::discover_flags_for(
        &cfg.openssl_path, subcmd_def.name, &excluded,
    )?;
    println!("  Discovered {} flags", flag_defs.len());

    // Apply overlay
    if let Ok(overlay) = flag_overlay::load_overlay(&cfg.flags_overlay_path) {
        flag_overlay::apply_overlay(&mut flag_defs, &overlay);
        println!("  Applied overlay from {}", cfg.flags_overlay_path);
    }

    // Build dictionary (embedded core + external files)
    let mut dict = dictionaries::Dictionary::embedded();
    println!("  Loaded {} embedded dictionary entries", dict.total_entries());

    for dict_path in &dict_files {
        match dict.load_file(dict_path) {
            Ok(count) => println!("  Loaded {} entries from '{}'", count, dict_path),
            Err(e) => eprintln!("  Warning: {}", e),
        }
    }

    // Enrich with seeds + dictionary
    flag_seeds::enrich_flags(&mut flag_defs, Some(&dict));
    println!("  Enriched flags with seed values");

    // Generate test fixtures for file-based subcommands
    let fixture_files = if subcmd_def.needs_input_files {
        let fixture_dir = "/tmp/openssl-fuzz-fixtures";
        println!("  Generating test fixtures in {}", fixture_dir);
        let files = subcommand::generate_fixtures(fixture_dir)
            .map_err(|e| anyhow::anyhow!("Failed to generate fixtures: {}", e))?;
        println!("  Created {} fixture files", files.len());

        // Add -in seeds for subcommands that take input files
        flag_seeds::add_input_file_seeds(&mut flag_defs, &files);

        files
    } else {
        Vec::new()
    };
    let _ = fixture_files; // suppress unused warning when not file-based

    // Start TLS server if needed (only for s_client)
    let state_dir = std::path::PathBuf::from("/tmp/openssl-fuzz-server-state");
    let _ = std::fs::create_dir_all(&state_dir);
    let mut _server_child: Option<std::process::Child> = None;

    if is_s_client && !no_servers {
        println!("\nStarting TLS test server...");

        // Generate certs
        let cert_dir = "/tmp/curl-fuzz-certs";
        let cert_output = std::process::Command::new("python3")
            .arg("-c")
            .arg(format!(
                "import sys; sys.path.insert(0,'test-servers'); from tls_wrapper import generate_cert; c,k = generate_cert('{}'); print(c); print(k)",
                cert_dir
            ))
            .output()?;
        let cert_stdout = String::from_utf8_lossy(&cert_output.stdout);
        let cert_lines: Vec<&str> = cert_stdout.trim().lines().collect();
        let (certfile, keyfile) = if cert_lines.len() >= 2 {
            (cert_lines[0].to_string(), cert_lines[1].to_string())
        } else {
            return Err(anyhow::anyhow!("Failed to generate TLS certs"));
        };
        println!("  TLS certificates generated");

        // Extract port from connect string
        let port = cfg.connect.rsplit(':').next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(8443);

        let child = std::process::Command::new("python3")
            .arg("test-servers/tls_server.py")
            .arg("--port").arg(port.to_string())
            .arg("--mode").arg(&server_mode)
            .arg("--state-dir").arg(&state_dir)
            .arg("--certfile").arg(&certfile)
            .arg("--keyfile").arg(&keyfile)
            .spawn()?;
        _server_child = Some(child);

        // Wait for server to start
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Health check
        if let Ok(stream) = std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", port).parse().unwrap(),
            std::time::Duration::from_secs(2),
        ) {
            drop(stream);
            println!("  TLS server started on port {} (mode={})", port, server_mode);
        } else {
            eprintln!("  Warning: TLS server health check failed on port {}", port);
        }
    }

    println!("\nStarting openssl fuzzer...");
    println!("  openssl binary: {}", cfg.openssl_path);
    println!("  Subcommand: {} ({})", subcmd_def.name, subcmd_def.description);
    if is_s_client {
        println!("  Connect: {}", cfg.connect);
        println!("  Server mode: {}", server_mode);
    }
    println!("  Population: {}", cfg.population_size);
    println!("  Generations: {}", cfg.max_generations);
    println!("  Mutation rate: {}", cfg.mutation_rate);
    println!("  Flags: {}", flag_defs.len());
    println!("  Database: {}", cfg.database_path);
    println!("  Findings dir: {}", cfg.findings_dir);
    println!();

    // Open database
    let db = FuzzDatabase::open(&cfg.database_path)?;

    let mut rng = match cfg.seed {
        Some(s) => StdRng::seed_from_u64(s),
        None => StdRng::from_entropy(),
    };

    // Create initial population
    let mut population = Vec::new();
    for _ in 0..cfg.population_size {
        population.push(OpenSslIndividual::random(
            &flag_defs, cfg.min_flags, cfg.max_active_flags, &mut rng,
        ));
    }

    let engine_config = EngineConfig {
        population_size: cfg.population_size,
        max_generations: cfg.max_generations,
        mutation_rate: cfg.mutation_rate,
        crossover_rate: cfg.crossover_rate,
        elitism_count: (cfg.population_size as f64 * cfg.elitism_percent) as usize,
        seed: cfg.seed,
    };

    let tournament = TournamentSelection::new(3);
    let crossover = OpenSslCrossover::new();
    let mutation = OpenSslMutation::new(cfg.mutation_rate, flag_defs.clone(), cfg.max_active_flags);

    let mut evaluator = OpenSslFitnessEvaluator::new_for_subcommand(
        cfg.openssl_path.clone(),
        subcmd_def.name.to_string(),
        subcmd_def.fixed_args.clone(),
        subcmd_def.stdin_input.map(|s| s.to_string()),
        cfg.timeout_ms,
    );
    evaluator.scorer = OpenSslFitnessScorer {
        crash_weight: cfg.weight_crash,
        sanitizer_weight: cfg.weight_sanitizer,
        exit_code_weight: cfg.weight_exit_code,
        timing_weight: cfg.weight_timing,
        tls_anomaly_weight: cfg.weight_tls_anomaly,
        memory_weight: cfg.weight_memory,
        ..OpenSslFitnessScorer::default()
    };
    if is_s_client && !no_servers && server_mode != "good" {
        evaluator.state_dir = Some(state_dir.to_string_lossy().to_string());
    }

    let engine = EvolutionEngine::new(engine_config);
    let start_time = std::time::Instant::now();
    let mut total_findings = 0usize;
    let _connect = cfg.connect.clone();
    let openssl_path = cfg.openssl_path.clone();
    let findings_dir = cfg.findings_dir.clone();
    let fitness_threshold = cfg.fitness_threshold;
    let max_generations = cfg.max_generations;
    let subcmd_name = subcmd_def.name.to_string();
    let subcmd_fixed_args = subcmd_def.fixed_args.clone();
    let subcmd_stdin = subcmd_def.stdin_input.map(|s| s.to_string());
    let subcmd_stdin_prefix = subcmd_def.stdin_input.map(|s| s.trim().to_string());

    let adaptive_config = AdaptiveMutationConfig {
        base_rate: cfg.mutation_rate,
        max_rate: cfg.mutation_rate * 5.0,
        stagnation_window: 20,
        spike_duration: 3,
    };

    let diversity_config = DiversityConfig::default();

    let _result = engine.run_adaptive(
        population,
        &evaluator,
        &tournament,
        &crossover,
        &mutation,
        adaptive_config,
        diversity_config,
        |gen, scored, is_spiking, current_rate, diversity| {
            let best = &scored[0];
            let worst = &scored[scored.len() - 1];
            let avg: f64 = scored.iter().map(|s| s.fitness.total).sum::<f64>() / scored.len() as f64;
            let elapsed = start_time.elapsed().as_secs();

            // Progress line
            let spike_indicator = if is_spiking { " SPIKE" } else { "" };
            print!("\rGen {}/{}: best={:.1} avg={:.1} worst={:.1} | findings={} div={:.0}% rate={:.3}{} elapsed={}s",
                gen + 1, max_generations,
                best.fitness.total, avg, worst.fitness.total,
                total_findings, diversity * 100.0, current_rate, spike_indicator, elapsed,
            );
            use std::io::Write;
            let _ = std::io::stdout().flush();

            // Re-execute best individual to capture actual execution data for the record
            let openssl_command = best.individual.to_command_string_for(
                &openssl_path, &subcmd_name, &subcmd_fixed_args,
                subcmd_stdin_prefix.as_deref(),
            );
            let components_json = serde_json::to_string(&best.fitness.components).unwrap_or_default();
            let best_args = best.individual.to_args();

            let (exit_code, signal, duration_ms, _stdout, stderr) =
                match crate::executor::execute_openssl_cmd(
                    &openssl_path, &subcmd_name, &subcmd_fixed_args, &best_args,
                    subcmd_stdin.as_deref(), cfg.timeout_ms,
                ) {
                    Ok(r) => (r.exit_code, r.signal, r.duration_ms, r.stdout, r.stderr),
                    Err(_) => (0, None, 0, String::new(), String::new()),
                };

            let run_record = RunRecord {
                generation: gen,
                individual_id: 0,
                openssl_command: openssl_command.clone(),
                fitness_total: best.fitness.total,
                fitness_components: components_json,
                exit_code,
                signal,
                duration_ms,
                stdout: String::new(), // don't store full output in DB
                stderr: stderr.chars().take(500).collect(), // truncate for DB
                created_at: None,
            };

            let _ = db.insert_run(&run_record);

            // Write finding if above threshold
            if best.fitness.total >= fitness_threshold {
                let malformation_note = best.fitness.metadata.get("server_malformation")
                    .map(|m| format!("\nServer malformation: {}", m))
                    .unwrap_or_default();
                if let Ok(filename) = write_finding(
                    &findings_dir, gen, 0, &openssl_command,
                    best.fitness.total, exit_code, signal,
                    &format!("Fitness components: {:?}{}", best.fitness.components, malformation_note),
                ) {
                    total_findings += 1;
                    println!("\n  Finding: {:.2} -> {}", best.fitness.total, filename);
                }
            }

            // Print details if interesting finding
            if best.fitness.total > 10.0 {
                println!();
                println!("  >> {}", best.individual.to_command_string_for(
                    &openssl_path, &subcmd_name, &subcmd_fixed_args,
                    subcmd_stdin_prefix.as_deref(),
                ));
                for (name, value) in &best.fitness.components {
                    println!("     {}: {:.1}", name, value);
                }
            }

            true
        },
    );

    println!("\n\n=== Fuzzing Complete ===");
    println!("Best fitness: {:.2}", scored_best_fitness(&db));
    println!("Total findings (>= {:.2}): {}", cfg.fitness_threshold, total_findings);
    println!("Database: {}", cfg.database_path);
    println!("Findings directory: {}", cfg.findings_dir);

    // Stop TLS server
    if let Some(ref mut child) = _server_child {
        let _ = child.kill();
    }

    Ok(())
}

fn scored_best_fitness(db: &persistence::FuzzDatabase) -> f64 {
    db.get_top_findings(1)
        .ok()
        .and_then(|v| v.first().map(|r| r.fitness_total))
        .unwrap_or(0.0)
}
