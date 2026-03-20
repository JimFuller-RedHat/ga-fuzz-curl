use crate::flag_def::OpenSslFlagDef;
use ga_engine::adaptive::RateControl;
use ga_engine::gene::Gene;
use ga_engine::traits::{Individual, CrossoverOperator, MutationOperator};
use ga_engine::crossover::UniformCrossover;
use rand::Rng;
use std::cell::Cell;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct OpenSslIndividual {
    pub genes: Vec<Gene>,
    pub flag_defs: Vec<OpenSslFlagDef>,
}

impl Individual for OpenSslIndividual {
    fn chromosome(&self) -> &[Gene] {
        &self.genes
    }
    fn chromosome_mut(&mut self) -> &mut Vec<Gene> {
        &mut self.genes
    }
}

impl OpenSslIndividual {
    pub fn random(
        flag_defs: &[OpenSslFlagDef],
        min_active: usize,
        max_active: usize,
        rng: &mut impl Rng,
    ) -> Self {
        let n = flag_defs.len();
        let active_count = rng.gen_range(min_active..=max_active.min(n));

        let mut indices: Vec<usize> = (0..n).collect();
        for i in 0..active_count.min(n) {
            let j = rng.gen_range(i..n);
            indices.swap(i, j);
        }
        let active: HashSet<usize> = indices[..active_count].iter().copied().collect();

        let genes = (0..n)
            .map(|idx| {
                if active.contains(&idx) {
                    flag_defs[idx].random_gene(rng)
                } else {
                    Gene::Absent
                }
            })
            .collect();

        Self {
            genes,
            flag_defs: flag_defs.to_vec(),
        }
    }

    pub fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        for (gene, flag) in self.genes.iter().zip(self.flag_defs.iter()) {
            match gene {
                Gene::Absent | Gene::Boolean(false) => {}
                Gene::Boolean(true) => {
                    args.push(flag.name.clone());
                }
                Gene::Discrete(val) => {
                    args.push(flag.name.clone());
                    args.push(val.clone());
                }
                Gene::Integer(val) => {
                    args.push(flag.name.clone());
                    args.push(val.to_string());
                }
                Gene::Float(val) => {
                    args.push(flag.name.clone());
                    args.push(val.to_string());
                }
            }
        }
        args
    }

    pub fn to_command_string(&self, openssl_path: &str, connect: &str) -> String {
        self.to_command_string_for(openssl_path, "s_client",
            &["-connect".to_string(), connect.to_string()], Some("Q"))
    }

    pub fn to_command_string_for(
        &self,
        openssl_path: &str,
        subcommand: &str,
        fixed_args: &[String],
        stdin_prefix: Option<&str>,
    ) -> String {
        let args = self.to_args();
        let fixed = if fixed_args.is_empty() {
            String::new()
        } else {
            format!(" {}", fixed_args.join(" "))
        };
        let fuzzed = if args.is_empty() {
            String::new()
        } else {
            format!(" {}", args.join(" "))
        };
        match stdin_prefix {
            Some(prefix) => format!("echo {} | {} {}{}{}", prefix, openssl_path, subcommand, fixed, fuzzed),
            None => format!("{} {}{}{}", openssl_path, subcommand, fixed, fuzzed),
        }
    }
}

pub struct OpenSslCrossover {
    inner: UniformCrossover,
}

impl OpenSslCrossover {
    pub fn new() -> Self {
        Self { inner: UniformCrossover::new() }
    }
}

impl CrossoverOperator<OpenSslIndividual> for OpenSslCrossover {
    fn crossover(&self, a: &OpenSslIndividual, b: &OpenSslIndividual, rng: &mut impl Rng) -> OpenSslIndividual {
        self.inner.crossover(a, b, rng)
    }
}

pub struct OpenSslMutation {
    rate: Cell<f64>,
    pub flag_defs: Vec<OpenSslFlagDef>,
    pub max_active: usize,
}

impl OpenSslMutation {
    pub fn new(rate: f64, flag_defs: Vec<OpenSslFlagDef>, max_active: usize) -> Self {
        Self { rate: Cell::new(rate), flag_defs, max_active }
    }
}

impl RateControl for OpenSslMutation {
    fn set_rate(&self, rate: f64) {
        self.rate.set(rate);
    }
    fn rate(&self) -> f64 {
        self.rate.get()
    }
}

impl MutationOperator<OpenSslIndividual> for OpenSslMutation {
    fn mutate(&self, individual: &mut OpenSslIndividual, rng: &mut impl Rng) {
        let rate = self.rate.get();
        for i in 0..individual.genes.len() {
            if rng.gen_bool(rate) {
                match &individual.genes[i] {
                    Gene::Absent => {
                        let active = individual.genes.iter()
                            .filter(|g| !matches!(g, Gene::Absent))
                            .count();
                        if active < self.max_active {
                            individual.genes[i] = self.flag_defs[i].random_gene(rng);
                        }
                    }
                    _ => {
                        if rng.gen_bool(0.3) {
                            individual.genes[i] = Gene::Absent;
                        } else {
                            individual.genes[i] = self.flag_defs[i].random_gene(rng);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flag_def::OpenSslFlagDef;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn sample_flags() -> Vec<OpenSslFlagDef> {
        vec![
            OpenSslFlagDef::boolean("-tls1_2"),
            OpenSslFlagDef::boolean("-tls1_3"),
            OpenSslFlagDef::discrete("-cipher", &["ALL", "HIGH"]),
            OpenSslFlagDef::integer("-verify", 0, 10),
            OpenSslFlagDef::boolean("-debug"),
        ]
    }

    #[test]
    fn test_random_individual() {
        let flags = sample_flags();
        let mut rng = StdRng::seed_from_u64(42);
        let ind = OpenSslIndividual::random(&flags, 2, 4, &mut rng);
        assert_eq!(ind.genes.len(), 5);
        let active = ind.genes.iter().filter(|g| !matches!(g, Gene::Absent)).count();
        assert!(active >= 2 && active <= 4);
    }

    #[test]
    fn test_to_args_boolean() {
        let flags = vec![OpenSslFlagDef::boolean("-tls1_2")];
        let ind = OpenSslIndividual {
            genes: vec![Gene::Boolean(true)],
            flag_defs: flags,
        };
        assert_eq!(ind.to_args(), vec!["-tls1_2"]);
    }

    #[test]
    fn test_to_args_discrete() {
        let flags = vec![OpenSslFlagDef::discrete("-cipher", &["ALL"])];
        let ind = OpenSslIndividual {
            genes: vec![Gene::Discrete("ALL".into())],
            flag_defs: flags,
        };
        assert_eq!(ind.to_args(), vec!["-cipher", "ALL"]);
    }

    #[test]
    fn test_to_args_integer() {
        let flags = vec![OpenSslFlagDef::integer("-verify", 0, 10)];
        let ind = OpenSslIndividual {
            genes: vec![Gene::Integer(5)],
            flag_defs: flags,
        };
        assert_eq!(ind.to_args(), vec!["-verify", "5"]);
    }

    #[test]
    fn test_to_args_absent_skipped() {
        let flags = vec![
            OpenSslFlagDef::boolean("-tls1_2"),
            OpenSslFlagDef::boolean("-debug"),
        ];
        let ind = OpenSslIndividual {
            genes: vec![Gene::Absent, Gene::Boolean(true)],
            flag_defs: flags,
        };
        assert_eq!(ind.to_args(), vec!["-debug"]);
    }

    #[test]
    fn test_command_string() {
        let flags = vec![OpenSslFlagDef::boolean("-tls1_2")];
        let ind = OpenSslIndividual {
            genes: vec![Gene::Boolean(true)],
            flag_defs: flags,
        };
        let cmd = ind.to_command_string("openssl", "localhost:8443");
        assert_eq!(cmd, "echo Q | openssl s_client -connect localhost:8443 -tls1_2");
    }

    #[test]
    fn test_mutation_changes_genes() {
        let flags = sample_flags();
        let mut rng = StdRng::seed_from_u64(42);
        let mut ind = OpenSslIndividual::random(&flags, 3, 5, &mut rng);
        let before = ind.genes.clone();

        let mutation = OpenSslMutation::new(0.5, flags, 5);
        mutation.mutate(&mut ind, &mut rng);

        assert_ne!(ind.genes, before);
    }
}
