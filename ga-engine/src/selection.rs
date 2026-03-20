use crate::traits::{Individual, SelectionStrategy, Scored};
use rand::Rng;

/// Tournament selection - picks tournament_size random individuals and returns the fittest
#[derive(Debug, Clone)]
pub struct TournamentSelection {
    pub tournament_size: usize,
}

impl TournamentSelection {
    pub fn new(tournament_size: usize) -> Self {
        Self { tournament_size }
    }
}

impl<I: Individual> SelectionStrategy<I> for TournamentSelection {
    fn select<'a>(&self, population: &'a [Scored<I>], rng: &mut impl Rng) -> &'a I {
        let mut best_idx = rng.gen_range(0..population.len());
        let mut best_fitness = &population[best_idx].fitness;

        for _ in 1..self.tournament_size {
            let idx = rng.gen_range(0..population.len());
            if population[idx].fitness > *best_fitness {
                best_idx = idx;
                best_fitness = &population[idx].fitness;
            }
        }

        &population[best_idx].individual
    }
}

/// Roulette wheel selection - probability proportional to fitness
#[derive(Debug, Clone)]
pub struct RouletteWheelSelection;

impl RouletteWheelSelection {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RouletteWheelSelection {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: Individual> SelectionStrategy<I> for RouletteWheelSelection {
    fn select<'a>(&self, population: &'a [Scored<I>], rng: &mut impl Rng) -> &'a I {
        // Calculate total fitness
        let total_fitness: f64 = population.iter().map(|s| s.fitness.total).sum();

        // Handle edge case where all fitness is 0 or negative
        if total_fitness <= 0.0 {
            let idx = rng.gen_range(0..population.len());
            return &population[idx].individual;
        }

        // Spin the wheel
        let mut spin = rng.gen::<f64>() * total_fitness;

        for scored in population {
            spin -= scored.fitness.total;
            if spin <= 0.0 {
                return &scored.individual;
            }
        }

        // Fallback (shouldn't happen due to floating point precision)
        &population[population.len() - 1].individual
    }
}

/// Rank-based selection - probability proportional to rank
#[derive(Debug, Clone)]
pub struct RankBasedSelection;

impl RankBasedSelection {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RankBasedSelection {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: Individual> SelectionStrategy<I> for RankBasedSelection {
    fn select<'a>(&self, population: &'a [Scored<I>], rng: &mut impl Rng) -> &'a I {
        // Assuming population is sorted with best first, assign ranks
        // Best individual gets rank N, worst gets rank 1
        let n = population.len();
        let total_rank: usize = (n * (n + 1)) / 2; // Sum of 1..=n

        // Spin the wheel based on ranks
        let mut spin = rng.gen_range(0..total_rank);

        for (idx, scored) in population.iter().enumerate() {
            let rank = n - idx; // Best (idx=0) gets highest rank
            if spin < rank {
                return &scored.individual;
            }
            spin -= rank;
        }

        // Fallback
        &population[population.len() - 1].individual
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fitness::FitnessScore;
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

    fn create_test_population() -> Vec<Scored<TestIndividual>> {
        vec![
            Scored::new(
                TestIndividual {
                    chromosome: vec![Gene::Integer(100)],
                },
                FitnessScore::new(100.0),
            ),
            Scored::new(
                TestIndividual {
                    chromosome: vec![Gene::Integer(50)],
                },
                FitnessScore::new(50.0),
            ),
            Scored::new(
                TestIndividual {
                    chromosome: vec![Gene::Integer(25)],
                },
                FitnessScore::new(25.0),
            ),
            Scored::new(
                TestIndividual {
                    chromosome: vec![Gene::Integer(10)],
                },
                FitnessScore::new(10.0),
            ),
        ]
    }

    #[test]
    fn test_tournament_selects_from_population() {
        let population = create_test_population();
        let selector = TournamentSelection::new(2);
        let mut rng = StdRng::seed_from_u64(42);

        let selected = selector.select(&population, &mut rng);

        // Verify selected individual is from the population
        let valid = population.iter().any(|s| {
            std::ptr::eq(s.individual.chromosome(), selected.chromosome())
        });
        assert!(valid);
    }

    #[test]
    fn test_tournament_favors_fitter() {
        let population = create_test_population();
        // Larger tournament size means we should favor fitter individuals
        let selector = TournamentSelection::new(population.len());
        let mut rng = StdRng::seed_from_u64(42);

        let mut best_count = 0;
        let mut second_best_count = 0;
        for _ in 0..100 {
            let selected = selector.select(&population, &mut rng);
            if let Gene::Integer(val) = selected.chromosome()[0] {
                if val == 100 {
                    best_count += 1;
                } else if val == 50 {
                    second_best_count += 1;
                }
            }
        }

        // With tournament size = population size, should strongly favor best individuals
        // Due to sampling with replacement, we won't always pick the absolute best,
        // but should heavily favor top individuals
        assert!(best_count + second_best_count >= 80);
        assert!(best_count > 30); // Should pick best at least sometimes
    }

    #[test]
    fn test_roulette_selects_from_population() {
        let population = create_test_population();
        let selector = RouletteWheelSelection::new();
        let mut rng = StdRng::seed_from_u64(42);

        for _ in 0..10 {
            let selected = selector.select(&population, &mut rng);

            // Verify selected individual is from the population
            let valid = population.iter().any(|s| {
                std::ptr::eq(s.individual.chromosome(), selected.chromosome())
            });
            assert!(valid);
        }
    }

    #[test]
    fn test_rank_based_selects_from_population() {
        let population = create_test_population();
        let selector = RankBasedSelection::new();
        let mut rng = StdRng::seed_from_u64(42);

        for _ in 0..10 {
            let selected = selector.select(&population, &mut rng);

            // Verify selected individual is from the population
            let valid = population.iter().any(|s| {
                std::ptr::eq(s.individual.chromosome(), selected.chromosome())
            });
            assert!(valid);
        }
    }
}
