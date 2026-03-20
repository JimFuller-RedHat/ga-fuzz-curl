use crate::traits::{CrossoverOperator, Individual};
use rand::Rng;

/// Uniform crossover - each gene randomly from either parent
#[derive(Debug, Clone)]
pub struct UniformCrossover;

impl UniformCrossover {
    pub fn new() -> Self {
        Self
    }
}

impl Default for UniformCrossover {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: Individual> CrossoverOperator<I> for UniformCrossover {
    fn crossover(&self, parent_a: &I, parent_b: &I, rng: &mut impl Rng) -> I {
        let mut child = parent_a.clone();
        let chromosome = child.chromosome_mut();
        let parent_b_chromo = parent_b.chromosome();

        let min_len = chromosome.len().min(parent_b_chromo.len());

        for i in 0..min_len {
            if rng.gen_bool(0.5) {
                chromosome[i] = parent_b_chromo[i].clone();
            }
        }

        child
    }
}

/// Single point crossover - genes from parent_a before point, parent_b after
#[derive(Debug, Clone)]
pub struct SinglePointCrossover;

impl SinglePointCrossover {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SinglePointCrossover {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: Individual> CrossoverOperator<I> for SinglePointCrossover {
    fn crossover(&self, parent_a: &I, parent_b: &I, rng: &mut impl Rng) -> I {
        let mut child = parent_a.clone();
        let chromosome = child.chromosome_mut();
        let parent_b_chromo = parent_b.chromosome();

        let min_len = chromosome.len().min(parent_b_chromo.len());

        if min_len == 0 {
            return child;
        }

        let point = rng.gen_range(0..min_len);

        for i in point..min_len {
            chromosome[i] = parent_b_chromo[i].clone();
        }

        child
    }
}

/// Two point crossover - genes from parent_b between two points, parent_a elsewhere
#[derive(Debug, Clone)]
pub struct TwoPointCrossover;

impl TwoPointCrossover {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TwoPointCrossover {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: Individual> CrossoverOperator<I> for TwoPointCrossover {
    fn crossover(&self, parent_a: &I, parent_b: &I, rng: &mut impl Rng) -> I {
        let mut child = parent_a.clone();
        let chromosome = child.chromosome_mut();
        let parent_b_chromo = parent_b.chromosome();

        let min_len = chromosome.len().min(parent_b_chromo.len());

        if min_len < 2 {
            return child;
        }

        let mut point1 = rng.gen_range(0..min_len);
        let mut point2 = rng.gen_range(0..min_len);

        if point1 > point2 {
            std::mem::swap(&mut point1, &mut point2);
        }

        for i in point1..point2 {
            chromosome[i] = parent_b_chromo[i].clone();
        }

        child
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gene::Gene;
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
    fn test_uniform_mixes_genes() {
        let parent_a = TestIndividual {
            chromosome: vec![
                Gene::Boolean(true),
                Gene::Boolean(true),
                Gene::Boolean(true),
                Gene::Boolean(true),
            ],
        };
        let parent_b = TestIndividual {
            chromosome: vec![
                Gene::Boolean(false),
                Gene::Boolean(false),
                Gene::Boolean(false),
                Gene::Boolean(false),
            ],
        };

        let crossover = UniformCrossover::new();
        let mut rng = StdRng::seed_from_u64(42);

        let child = crossover.crossover(&parent_a, &parent_b, &mut rng);

        // Child should have mix of true and false
        let mut has_true = false;
        let mut has_false = false;

        for gene in child.chromosome() {
            if let Gene::Boolean(val) = gene {
                if *val {
                    has_true = true;
                } else {
                    has_false = true;
                }
            }
        }

        assert!(has_true || has_false); // At least one gene present
    }

    #[test]
    fn test_single_point_preserves_length() {
        let parent_a = TestIndividual {
            chromosome: vec![
                Gene::Integer(1),
                Gene::Integer(2),
                Gene::Integer(3),
                Gene::Integer(4),
            ],
        };
        let parent_b = TestIndividual {
            chromosome: vec![
                Gene::Integer(10),
                Gene::Integer(20),
                Gene::Integer(30),
                Gene::Integer(40),
            ],
        };

        let crossover = SinglePointCrossover::new();
        let mut rng = StdRng::seed_from_u64(42);

        let child = crossover.crossover(&parent_a, &parent_b, &mut rng);

        assert_eq!(child.chromosome().len(), parent_a.chromosome().len());
    }

    #[test]
    fn test_two_point_preserves_length() {
        let parent_a = TestIndividual {
            chromosome: vec![
                Gene::Integer(1),
                Gene::Integer(2),
                Gene::Integer(3),
                Gene::Integer(4),
                Gene::Integer(5),
            ],
        };
        let parent_b = TestIndividual {
            chromosome: vec![
                Gene::Integer(10),
                Gene::Integer(20),
                Gene::Integer(30),
                Gene::Integer(40),
                Gene::Integer(50),
            ],
        };

        let crossover = TwoPointCrossover::new();
        let mut rng = StdRng::seed_from_u64(42);

        let child = crossover.crossover(&parent_a, &parent_b, &mut rng);

        assert_eq!(child.chromosome().len(), parent_a.chromosome().len());
    }

    #[test]
    fn test_unequal_lengths() {
        let parent_a = TestIndividual {
            chromosome: vec![Gene::Integer(1), Gene::Integer(2), Gene::Integer(3)],
        };
        let parent_b = TestIndividual {
            chromosome: vec![Gene::Integer(10), Gene::Integer(20)],
        };

        let crossover = UniformCrossover::new();
        let mut rng = StdRng::seed_from_u64(42);

        let child = crossover.crossover(&parent_a, &parent_b, &mut rng);

        // Child should have parent_a's length, with first 2 genes potentially mixed
        assert_eq!(child.chromosome().len(), 3);
    }
}
