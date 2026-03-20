use crate::adaptive::RateControl;
use crate::gene::Gene;
use crate::traits::{Individual, MutationOperator};
use rand::Rng;
use std::cell::Cell;

/// Per-gene mutation with configurable rate
#[derive(Debug, Clone)]
pub struct PerGeneMutation {
    rate: Cell<f64>,
}

impl PerGeneMutation {
    pub fn new(rate: f64) -> Self {
        Self { rate: Cell::new(rate) }
    }
}

impl RateControl for PerGeneMutation {
    fn set_rate(&self, rate: f64) {
        self.rate.set(rate);
    }
    fn rate(&self) -> f64 {
        self.rate.get()
    }
}

impl PerGeneMutation {
    fn mutate_gene(&self, gene: &mut Gene, rng: &mut impl Rng) {
        match gene {
            Gene::Boolean(ref mut val) => {
                *val = !*val;
            }
            Gene::Integer(ref mut val) => {
                let delta = rng.gen_range(-10..=10);
                *val = val.saturating_add(delta);
            }
            Gene::Float(ref mut val) => {
                let delta = rng.gen_range(-1.0..=1.0);
                *val += delta;
            }
            Gene::Discrete(_) | Gene::Absent => {
                // No mutation for Discrete and Absent
            }
        }
    }
}

impl<I: Individual> MutationOperator<I> for PerGeneMutation {
    fn mutate(&self, individual: &mut I, rng: &mut impl Rng) {
        let rate = self.rate.get();
        let chromosome = individual.chromosome_mut();

        for gene in chromosome.iter_mut() {
            if rng.gen_bool(rate) {
                self.mutate_gene(gene, rng);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[derive(Debug, Clone)]
    struct TestIndividual {
        chromosome: Vec<Gene>,
    }

    impl Individual for TestIndividual {
        fn chromosome(&self) -> &[Gene] {
            &self.chromosome
        }

        fn chromosome_mut(&mut self) -> &mut Vec<Gene> {
            &mut self.chromosome
        }
    }

    #[test]
    fn test_rate_zero_no_change() {
        let mut individual = TestIndividual {
            chromosome: vec![
                Gene::Boolean(true),
                Gene::Integer(42),
                Gene::Float(3.14),
            ],
        };
        let original = individual.clone();

        let mutator = PerGeneMutation::new(0.0);
        let mut rng = StdRng::seed_from_u64(42);

        mutator.mutate(&mut individual, &mut rng);

        assert_eq!(individual.chromosome(), original.chromosome());
    }

    #[test]
    fn test_rate_one_changes_booleans() {
        let mut individual = TestIndividual {
            chromosome: vec![
                Gene::Boolean(true),
                Gene::Boolean(false),
                Gene::Boolean(true),
            ],
        };

        let mutator = PerGeneMutation::new(1.0);
        let mut rng = StdRng::seed_from_u64(42);

        mutator.mutate(&mut individual, &mut rng);

        // All booleans should be flipped
        assert_eq!(individual.chromosome()[0], Gene::Boolean(false));
        assert_eq!(individual.chromosome()[1], Gene::Boolean(true));
        assert_eq!(individual.chromosome()[2], Gene::Boolean(false));
    }

    #[test]
    fn test_integer_mutation() {
        let mut individual = TestIndividual {
            chromosome: vec![Gene::Integer(100)],
        };

        let mutator = PerGeneMutation::new(1.0);
        let mut rng = StdRng::seed_from_u64(42);

        mutator.mutate(&mut individual, &mut rng);

        // Integer should have changed
        if let Gene::Integer(val) = individual.chromosome()[0] {
            assert_ne!(val, 100);
            assert!(val >= 90 && val <= 110); // Within delta range
        } else {
            panic!("Expected Integer gene");
        }
    }

    #[test]
    fn test_float_mutation() {
        let mut individual = TestIndividual {
            chromosome: vec![Gene::Float(10.0)],
        };

        let mutator = PerGeneMutation::new(1.0);
        let mut rng = StdRng::seed_from_u64(42);

        mutator.mutate(&mut individual, &mut rng);

        // Float should have changed
        if let Gene::Float(val) = individual.chromosome()[0] {
            assert_ne!(val, 10.0);
            assert!(val >= 9.0 && val <= 11.0); // Within delta range
        } else {
            panic!("Expected Float gene");
        }
    }

    #[test]
    fn test_discrete_unchanged() {
        let mut individual = TestIndividual {
            chromosome: vec![Gene::Discrete("GET".to_string())],
        };
        let original = individual.clone();

        let mutator = PerGeneMutation::new(1.0);
        let mut rng = StdRng::seed_from_u64(42);

        mutator.mutate(&mut individual, &mut rng);

        // Discrete should not change
        assert_eq!(individual.chromosome()[0], original.chromosome()[0]);
    }

    #[test]
    fn test_absent_unchanged() {
        let mut individual = TestIndividual {
            chromosome: vec![Gene::Absent],
        };
        let original = individual.clone();

        let mutator = PerGeneMutation::new(1.0);
        let mut rng = StdRng::seed_from_u64(42);

        mutator.mutate(&mut individual, &mut rng);

        // Absent should not change
        assert_eq!(individual.chromosome()[0], original.chromosome()[0]);
    }
}
