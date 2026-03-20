use crate::flags::{LsFlag, random_gene};
use ga_engine::adaptive::RateControl;
use ga_engine::gene::Gene;
use ga_engine::traits::{Individual, CrossoverOperator, MutationOperator};
use ga_engine::crossover::UniformCrossover;
use rand::Rng;
use std::cell::Cell;

#[derive(Debug, Clone)]
pub struct LsIndividual {
    pub genes: Vec<Gene>,
    pub flag_defs: Vec<LsFlag>,
}

impl Individual for LsIndividual {
    fn chromosome(&self) -> &[Gene] {
        &self.genes
    }
    fn chromosome_mut(&mut self) -> &mut Vec<Gene> {
        &mut self.genes
    }
}

impl LsIndividual {
    /// Create a random individual with some flags active
    pub fn random(flag_defs: &[LsFlag], min_active: usize, max_active: usize, rng: &mut impl Rng) -> Self {
        let n = flag_defs.len();
        let active_count = rng.gen_range(min_active..=max_active.min(n));

        let mut genes: Vec<Gene> = vec![Gene::Absent; n];

        // Randomly activate some flags
        let mut indices: Vec<usize> = (0..n).collect();
        // Fisher-Yates shuffle to pick random subset
        for i in 0..active_count {
            let j = rng.gen_range(i..n);
            indices.swap(i, j);
        }

        for i in 0..active_count {
            let idx = indices[i];
            genes[idx] = random_gene(&flag_defs[idx], rng);
        }

        Self {
            genes,
            flag_defs: flag_defs.to_vec(),
        }
    }

    /// Convert to ls command-line arguments
    pub fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        for (gene, flag) in self.genes.iter().zip(self.flag_defs.iter()) {
            match gene {
                Gene::Absent => {}
                Gene::Boolean(true) => {
                    args.push(flag.name.to_string());
                }
                Gene::Discrete(val) => {
                    if flag.name.starts_with("--") {
                        args.push(format!("{}={}", flag.name, val));
                    } else {
                        args.push(flag.name.to_string());
                        args.push(val.to_string());
                    }
                }
                _ => {}
            }
        }
        args
    }

    /// Format as full command string for display
    pub fn to_command_string(&self, ls_path: &str, target: &str) -> String {
        let args = self.to_args();
        format!("{} {} {}", ls_path, args.join(" "), target)
    }
}

/// Mutation: randomly flip flags on/off, change values
pub struct LsMutation {
    rate: Cell<f64>,
    pub flag_defs: Vec<LsFlag>,
    pub max_active: usize,
}

impl LsMutation {
    pub fn new(rate: f64, flag_defs: Vec<LsFlag>, max_active: usize) -> Self {
        Self { rate: Cell::new(rate), flag_defs, max_active }
    }
}

impl RateControl for LsMutation {
    fn set_rate(&self, rate: f64) {
        self.rate.set(rate);
    }
    fn rate(&self) -> f64 {
        self.rate.get()
    }
}

impl MutationOperator<LsIndividual> for LsMutation {
    fn mutate(&self, individual: &mut LsIndividual, rng: &mut impl Rng) {
        let rate = self.rate.get();
        for i in 0..individual.genes.len() {
            if rng.gen_bool(rate) {
                match &individual.genes[i] {
                    Gene::Absent => {
                        // Activate this flag
                        let active = individual.genes.iter().filter(|g| !matches!(g, Gene::Absent)).count();
                        if active < self.max_active {
                            individual.genes[i] = random_gene(&self.flag_defs[i], rng);
                        }
                    }
                    _ => {
                        // 30% chance to deactivate, 70% chance to re-randomize value
                        if rng.gen_bool(0.3) {
                            individual.genes[i] = Gene::Absent;
                        } else {
                            individual.genes[i] = random_gene(&self.flag_defs[i], rng);
                        }
                    }
                }
            }
        }
    }
}

/// Crossover: wraps UniformCrossover from ga-engine
pub struct LsCrossover {
    inner: UniformCrossover,
}

impl LsCrossover {
    pub fn new() -> Self {
        Self { inner: UniformCrossover::new() }
    }
}

impl CrossoverOperator<LsIndividual> for LsCrossover {
    fn crossover(&self, parent_a: &LsIndividual, parent_b: &LsIndividual, rng: &mut impl Rng) -> LsIndividual {
        self.inner.crossover(parent_a, parent_b, rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::{self, FlagValues};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_random_individual() {
        let flags = flags::all_flags();
        let mut rng = StdRng::seed_from_u64(42);
        let ind = LsIndividual::random(&flags, 3, 10, &mut rng);

        assert_eq!(ind.genes.len(), flags.len());
        let active = ind.genes.iter().filter(|g| !matches!(g, Gene::Absent)).count();
        assert!(active >= 3 && active <= 10);
    }

    #[test]
    fn test_to_args_bool_flag() {
        let flags = vec![
            LsFlag { name: "-l", values: FlagValues::Bool },
            LsFlag { name: "-a", values: FlagValues::Bool },
        ];
        let ind = LsIndividual {
            genes: vec![Gene::Boolean(true), Gene::Absent],
            flag_defs: flags,
        };
        assert_eq!(ind.to_args(), vec!["-l"]);
    }

    #[test]
    fn test_to_args_discrete_long_flag() {
        let flags = vec![
            LsFlag { name: "--color", values: FlagValues::Discrete(&["always"]) },
        ];
        let ind = LsIndividual {
            genes: vec![Gene::Discrete("always".into())],
            flag_defs: flags,
        };
        assert_eq!(ind.to_args(), vec!["--color=always"]);
    }

    #[test]
    fn test_to_args_discrete_short_flag() {
        let flags = vec![
            LsFlag { name: "-T", values: FlagValues::Discrete(&["4"]) },
        ];
        let ind = LsIndividual {
            genes: vec![Gene::Discrete("4".into())],
            flag_defs: flags,
        };
        assert_eq!(ind.to_args(), vec!["-T", "4"]);
    }

    #[test]
    fn test_mutation_changes_genes() {
        let flags = flags::all_flags();
        let mut rng = StdRng::seed_from_u64(42);
        let mut ind = LsIndividual::random(&flags, 5, 10, &mut rng);
        let before = ind.genes.clone();

        let mutation = LsMutation::new(0.5, flags, 20);
        mutation.mutate(&mut ind, &mut rng);

        // With 50% mutation rate, at least some genes should change
        assert_ne!(ind.genes, before);
    }

    #[test]
    fn test_command_string() {
        let flags = vec![
            LsFlag { name: "-l", values: FlagValues::Bool },
        ];
        let ind = LsIndividual {
            genes: vec![Gene::Boolean(true)],
            flag_defs: flags,
        };
        let cmd = ind.to_command_string("ls", "/tmp");
        assert_eq!(cmd, "ls -l /tmp");
    }
}
