mod flags;
mod individual;
mod executor;
mod fitness;
mod findings;
mod persistence;
mod test_fixtures;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ls-fuzzer")]
#[command(about = "Genetic algorithm fuzzer for ls")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the fuzzer
    Run {
        /// Path to ls binary
        #[arg(long, default_value = "ls")]
        ls_path: String,

        /// Target directory to list
        #[arg(long)]
        target: Option<String>,

        /// Population size
        #[arg(long, default_value = "50")]
        population_size: usize,

        /// Number of generations
        #[arg(long, default_value = "20")]
        generations: usize,

        /// Mutation rate
        #[arg(long, default_value = "0.05")]
        mutation_rate: f64,

        /// Crossover rate
        #[arg(long, default_value = "0.4")]
        crossover_rate: f64,

        /// Max active flags per individual
        #[arg(long, default_value = "15")]
        max_active_flags: usize,

        /// Per-execution timeout in ms
        #[arg(long, default_value = "5000")]
        timeout_ms: u64,

        /// Random seed
        #[arg(long)]
        seed: Option<u64>,

        /// Database path
        #[arg(long, default_value = "ls-fuzzer.db")]
        database_path: String,

        /// Findings output directory
        #[arg(long, default_value = "ls-findings")]
        findings_dir: String,

        /// Fitness threshold for saving findings
        #[arg(long, default_value = "5.0")]
        fitness_threshold: f64,
    },
    /// Generate a report of findings
    Report {
        /// Number of top findings to show
        #[arg(long, default_value = "10")]
        top: usize,

        /// Database path
        #[arg(long, default_value = "ls-fuzzer.db")]
        database_path: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            ls_path,
            target,
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
        } => {
            run_fuzzer(
                ls_path, target, population_size, generations,
                mutation_rate, crossover_rate, max_active_flags,
                timeout_ms, seed, database_path, findings_dir,
                fitness_threshold,
            )?;
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
        println!("\n=== Top {} ls-fuzzer Findings ===\n", top);
        println!("{:<5} {:<6} {:<10} {:<6} {:<8} {:<20} {}", "Gen", "Ind", "Fitness", "Exit", "Time", "When", "Command");
        println!("{:-<120}", "");

        for finding in &findings {
            let cmd_preview = if finding.ls_command.len() > 45 {
                format!("{}...", &finding.ls_command[..42])
            } else {
                finding.ls_command.clone()
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
    ls_path: String,
    target: Option<String>,
    population_size: usize,
    max_generations: usize,
    mutation_rate: f64,
    crossover_rate: f64,
    max_active_flags: usize,
    timeout_ms: u64,
    seed: Option<u64>,
    database_path: String,
    findings_dir: String,
    fitness_threshold: f64,
) -> Result<()> {
    use individual::{LsIndividual, LsCrossover, LsMutation};
    use fitness::LsFitnessEvaluator;
    use persistence::{FuzzDatabase, RunRecord};
    use findings::write_finding;
    use ga_engine::adaptive::{AdaptiveMutationConfig, DiversityConfig};
    use ga_engine::engine::{EngineConfig, EvolutionEngine};
    use ga_engine::selection::TournamentSelection;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // Create test fixtures if no target specified
    let fixtures = if target.is_none() {
        println!("Creating test fixtures...");
        let f = test_fixtures::TestFixtures::create()
            .map_err(|e| anyhow::anyhow!("Failed to create fixtures: {}", e))?;
        println!("  Fixtures at: {}", f.path().display());
        Some(f)
    } else {
        None
    };

    let target_path = match &target {
        Some(t) => t.clone(),
        None => fixtures.as_ref().unwrap().path().to_string_lossy().to_string(),
    };

    let flag_defs = flags::all_flags();

    println!("Starting ls fuzzer...");
    println!("  ls binary: {}", ls_path);
    println!("  Target: {}", target_path);
    println!("  Population: {}", population_size);
    println!("  Generations: {}", max_generations);
    println!("  Mutation rate: {}", mutation_rate);
    println!("  Flags: {}", flag_defs.len());
    println!("  Database: {}", database_path);
    println!("  Findings dir: {}", findings_dir);
    println!();

    // Open database
    let db = FuzzDatabase::open(&database_path)?;

    let mut rng = match seed {
        Some(s) => StdRng::seed_from_u64(s),
        None => StdRng::from_entropy(),
    };

    // Create initial population
    let mut population = Vec::new();
    for _ in 0..population_size {
        population.push(LsIndividual::random(&flag_defs, 2, max_active_flags, &mut rng));
    }

    let engine_config = EngineConfig {
        population_size,
        max_generations,
        mutation_rate,
        crossover_rate,
        elitism_count: (population_size as f64 * 0.1) as usize,
        seed,
    };

    let tournament = TournamentSelection::new(3);
    let crossover = LsCrossover::new();
    let mutation = LsMutation::new(mutation_rate, flag_defs, max_active_flags);
    let evaluator = LsFitnessEvaluator::new(ls_path.clone(), target_path.clone(), timeout_ms);

    let engine = EvolutionEngine::new(engine_config);
    let start_time = std::time::Instant::now();
    let mut total_findings = 0usize;

    let adaptive_config = AdaptiveMutationConfig {
        base_rate: mutation_rate,
        max_rate: mutation_rate * 5.0,
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

            // Persist best individual
            let ls_command = best.individual.to_command_string(&ls_path, &target_path);
            let components_json = serde_json::to_string(&best.fitness.components).unwrap_or_default();

            let run_record = RunRecord {
                generation: gen,
                individual_id: 0,
                ls_command: ls_command.clone(),
                fitness_total: best.fitness.total,
                fitness_components: components_json,
                exit_code: 0,
                signal: None,
                duration_ms: 0,
                stderr: String::new(),
                created_at: None,
            };

            let _ = db.insert_run(&run_record);

            // Write finding if above threshold
            if best.fitness.total >= fitness_threshold {
                if let Ok(filename) = write_finding(
                    &findings_dir, gen, 0, &ls_command,
                    best.fitness.total, 0, None,
                    &format!("Fitness components: {:?}", best.fitness.components),
                ) {
                    total_findings += 1;
                    println!("\n  Finding: {:.2} -> {}", best.fitness.total, filename);
                }
            }

            // Print details if interesting finding
            if best.fitness.total > 5.0 {
                println!();
                println!("  >> {}", best.individual.to_command_string(&ls_path, &target_path));
                for (name, value) in &best.fitness.components {
                    println!("     {}: {:.1}", name, value);
                }
            }

            true
        },
    );

    println!("\n\n=== Fuzzing Complete ===");
    println!("Best fitness: {:.2}", scored_best_fitness(&db));
    println!("Total findings (>= {:.2}): {}", fitness_threshold, total_findings);
    println!("Database: {}", database_path);
    println!("Findings directory: {}", findings_dir);

    // Keep fixtures alive until here
    drop(fixtures);

    Ok(())
}

fn scored_best_fitness(db: &persistence::FuzzDatabase) -> f64 {
    db.get_top_findings(1)
        .ok()
        .and_then(|v| v.first().map(|r| r.fitness_total))
        .unwrap_or(0.0)
}
