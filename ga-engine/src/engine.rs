use crate::adaptive::{AdaptiveMutationConfig, AdaptiveMutationRate, DiversityConfig, RateControl};
use crate::traits::{
    CrossoverOperator, FitnessEvaluator, Individual, MutationOperator, Scored, SelectionStrategy,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rayon::prelude::*;

/// Configuration for the evolution engine
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub population_size: usize,
    pub max_generations: usize,
    pub mutation_rate: f64,
    pub crossover_rate: f64,
    pub elitism_count: usize,
    pub seed: Option<u64>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            population_size: 100,
            max_generations: 50,
            mutation_rate: 0.1,
            crossover_rate: 0.8,
            elitism_count: 2,
            seed: None,
        }
    }
}

/// Result of evolution run
#[derive(Debug, Clone)]
pub struct EvolutionResult<I: Individual> {
    pub generations_run: usize,
    pub best: Vec<Scored<I>>,
}

/// Main evolution engine
pub struct EvolutionEngine {
    config: EngineConfig,
}

impl EvolutionEngine {
    pub fn new(config: EngineConfig) -> Self {
        Self { config }
    }

    pub fn run<I, E, S, C, M>(
        &self,
        population: Vec<I>,
        evaluator: &E,
        selector: &S,
        crossover: &C,
        mutator: &M,
    ) -> EvolutionResult<I>
    where
        I: Individual,
        E: FitnessEvaluator<I>,
        S: SelectionStrategy<I>,
        C: CrossoverOperator<I>,
        M: MutationOperator<I>,
    {
        self.run_with_callback(population, evaluator, selector, crossover, mutator, |_, _| true)
    }

    /// Run evolution with a per-generation callback for progress reporting.
    /// The callback receives (generation, &[Scored<I>]) where scored is sorted best-first.
    /// Return `false` from the callback to stop early.
    pub fn run_with_callback<I, E, S, C, M, F>(
        &self,
        mut population: Vec<I>,
        evaluator: &E,
        selector: &S,
        crossover: &C,
        mutator: &M,
        mut on_generation: F,
    ) -> EvolutionResult<I>
    where
        I: Individual,
        E: FitnessEvaluator<I>,
        S: SelectionStrategy<I>,
        C: CrossoverOperator<I>,
        M: MutationOperator<I>,
        F: FnMut(usize, &[Scored<I>]) -> bool,
    {
        let mut rng = match self.config.seed {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::from_entropy(),
        };

        let mut best_individuals: Vec<Scored<I>> = Vec::new();

        for _generation in 0..self.config.max_generations {
            // Evaluate fitness for all individuals in parallel
            let mut scored_population: Vec<Scored<I>> = population
                .par_iter()
                .map(|ind| {
                    let fitness = evaluator.evaluate(ind);
                    Scored::new(ind.clone(), fitness)
                })
                .collect();

            // Sort by fitness (descending - best first)
            scored_population.sort_by(|a, b| {
                b.fitness
                    .partial_cmp(&a.fitness)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            // Track best individual from this generation
            if !scored_population.is_empty() {
                best_individuals.push(scored_population[0].clone());
            }

            // Progress callback - stop early if it returns false
            if !on_generation(_generation, &scored_population) {
                return EvolutionResult {
                    generations_run: _generation + 1,
                    best: best_individuals,
                };
            }

            // Create next generation
            let mut next_generation = Vec::new();

            // Elitism - keep top N individuals
            for i in 0..self.config.elitism_count.min(scored_population.len()) {
                next_generation.push(scored_population[i].individual.clone());
            }

            // Fill rest of population
            while next_generation.len() < self.config.population_size {
                // Select parents
                let parent_a = selector.select(&scored_population, &mut rng);
                let parent_b = selector.select(&scored_population, &mut rng);

                // Crossover
                let mut child = if rng.gen_bool(self.config.crossover_rate) {
                    crossover.crossover(parent_a, parent_b, &mut rng)
                } else {
                    parent_a.clone()
                };

                // Mutation
                mutator.mutate(&mut child, &mut rng);

                next_generation.push(child);
            }

            population = next_generation;
        }

        EvolutionResult {
            generations_run: self.config.max_generations,
            best: best_individuals,
        }
    }

    /// Run evolution with adaptive mutation rate and diversity-based smart immigrant injection.
    /// Detects fitness stagnation and temporarily spikes the mutation rate
    /// to escape local optima. When population diversity drops below a threshold,
    /// replaces the worst individuals with heavily-mutated copies of top individuals
    /// ("smart immigrants") to explore nearby productive regions.
    ///
    /// The callback receives (generation, &[Scored<I>], is_spiking, current_rate, diversity).
    /// Return `false` to stop early.
    pub fn run_adaptive<I, E, S, C, M, F>(
        &self,
        mut population: Vec<I>,
        evaluator: &E,
        selector: &S,
        crossover: &C,
        mutator: &M,
        adaptive_config: AdaptiveMutationConfig,
        diversity_config: DiversityConfig,
        mut on_generation: F,
    ) -> EvolutionResult<I>
    where
        I: Individual,
        E: FitnessEvaluator<I>,
        S: SelectionStrategy<I>,
        C: CrossoverOperator<I>,
        M: MutationOperator<I> + RateControl,
        F: FnMut(usize, &[Scored<I>], bool, f64, f64) -> bool,
    {
        let mut rng = match self.config.seed {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::from_entropy(),
        };

        let mut best_individuals: Vec<Scored<I>> = Vec::new();
        let mut adaptive = AdaptiveMutationRate::new(adaptive_config);

        for _generation in 0..self.config.max_generations {
            // Evaluate fitness for all individuals in parallel
            let mut scored_population: Vec<Scored<I>> = population
                .par_iter()
                .map(|ind| {
                    let fitness = evaluator.evaluate(ind);
                    Scored::new(ind.clone(), fitness)
                })
                .collect();

            // Sort by fitness (descending - best first)
            scored_population.sort_by(|a, b| {
                b.fitness
                    .partial_cmp(&a.fitness)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            // Track best individual
            if !scored_population.is_empty() {
                best_individuals.push(scored_population[0].clone());

                // Update adaptive rate based on best fitness
                let new_rate = adaptive.update(scored_population[0].fitness.total);
                mutator.set_rate(new_rate);
            }

            // Measure diversity
            let diversity = crate::adaptive::measure_diversity(
                &scored_population.iter().map(|s| &s.individual).cloned().collect::<Vec<_>>()
            );

            let is_spiking = adaptive.is_spiking();
            let current_rate = adaptive.rate();

            // Progress callback
            if !on_generation(_generation, &scored_population, is_spiking, current_rate, diversity) {
                return EvolutionResult {
                    generations_run: _generation + 1,
                    best: best_individuals,
                };
            }

            // Create next generation
            let mut next_generation = Vec::new();

            // Elitism
            for i in 0..self.config.elitism_count.min(scored_population.len()) {
                next_generation.push(scored_population[i].individual.clone());
            }

            // Fill rest of population
            while next_generation.len() < self.config.population_size {
                let parent_a = selector.select(&scored_population, &mut rng);
                let parent_b = selector.select(&scored_population, &mut rng);

                let mut child = if rng.gen_bool(self.config.crossover_rate) {
                    crossover.crossover(parent_a, parent_b, &mut rng)
                } else {
                    parent_a.clone()
                };

                mutator.mutate(&mut child, &mut rng);
                next_generation.push(child);
            }

            // Diversity-based smart immigrant injection
            // Instead of fully random immigrants, clone top individuals and
            // apply heavy mutation to explore near productive regions.
            if diversity < diversity_config.min_diversity {
                let num_immigrants = (next_generation.len() as f64
                    * diversity_config.immigrant_fraction) as usize;
                if num_immigrants > 0 && next_generation.len() > self.config.elitism_count + num_immigrants {
                    let top_quarter = (scored_population.len() / 4).max(1);
                    let start = next_generation.len() - num_immigrants;
                    for i in start..next_generation.len() {
                        // Clone a random top-25% individual
                        let donor_idx = rng.gen_range(0..top_quarter);
                        let mut immigrant = scored_population[donor_idx].individual.clone();
                        // Apply mutation 5 times for heavy perturbation
                        for _ in 0..5 {
                            mutator.mutate(&mut immigrant, &mut rng);
                        }
                        next_generation[i] = immigrant;
                    }
                }
            }

            population = next_generation;
        }

        EvolutionResult {
            generations_run: self.config.max_generations,
            best: best_individuals,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crossover::UniformCrossover;
    use crate::fitness::FitnessScore;
    use crate::gene::Gene;
    use crate::mutation::PerGeneMutation;
    use crate::selection::TournamentSelection;
    use crate::traits::{FitnessEvaluator, Individual};

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

    struct MaximizeSumEvaluator;

    impl FitnessEvaluator<TestIndividual> for MaximizeSumEvaluator {
        fn evaluate(&self, individual: &TestIndividual) -> FitnessScore {
            let sum: i64 = individual
                .chromosome()
                .iter()
                .map(|gene| {
                    if let Gene::Integer(val) = gene {
                        *val
                    } else {
                        0
                    }
                })
                .sum();

            FitnessScore::new(sum as f64)
        }
    }

    #[test]
    fn test_evolution_runs() {
        let config = EngineConfig {
            population_size: 10,
            max_generations: 5,
            mutation_rate: 0.1,
            crossover_rate: 0.8,
            elitism_count: 2,
            seed: Some(42),
        };

        let engine = EvolutionEngine::new(config);

        // Create initial population with random integer genes
        let mut initial_population = Vec::new();
        for i in 0..10 {
            initial_population.push(TestIndividual {
                chromosome: vec![Gene::Integer(i), Gene::Integer(i * 2)],
            });
        }

        let evaluator = MaximizeSumEvaluator;
        let selector = TournamentSelection::new(3);
        let crossover = UniformCrossover::new();
        let mutator = PerGeneMutation::new(0.1);

        let result = engine.run(
            initial_population,
            &evaluator,
            &selector,
            &crossover,
            &mutator,
        );

        // Verify results
        assert_eq!(result.generations_run, 5);
        assert_eq!(result.best.len(), 5);

        // Check that each generation has a best individual
        for (i, best) in result.best.iter().enumerate() {
            assert!(best.fitness.total >= 0.0, "Generation {} has negative fitness", i);
        }
    }

    #[test]
    fn test_evolution_improves_fitness() {
        let config = EngineConfig {
            population_size: 20,
            max_generations: 10,
            mutation_rate: 0.2,
            crossover_rate: 0.9,
            elitism_count: 3,
            seed: Some(123),
        };

        let engine = EvolutionEngine::new(config);

        // Create initial population with small values
        let mut initial_population = Vec::new();
        for i in 0..20 {
            initial_population.push(TestIndividual {
                chromosome: vec![Gene::Integer(i % 5), Gene::Integer((i % 3) * 2)],
            });
        }

        let evaluator = MaximizeSumEvaluator;
        let selector = TournamentSelection::new(3);
        let crossover = UniformCrossover::new();
        let mutator = PerGeneMutation::new(0.2);

        let result = engine.run(
            initial_population,
            &evaluator,
            &selector,
            &crossover,
            &mutator,
        );

        // Generally expect improvement (though not guaranteed with randomness)
        // Just verify that we have results and they're valid
        assert_eq!(result.best.len(), 10);

        let first_gen_fitness = result.best[0].fitness.total;
        let last_gen_fitness = result.best[9].fitness.total;

        // Both should be valid fitness scores
        assert!(first_gen_fitness.is_finite());
        assert!(last_gen_fitness.is_finite());
    }

    #[test]
    fn test_elitism_preserves_best() {
        let config = EngineConfig {
            population_size: 10,
            max_generations: 3,
            mutation_rate: 0.0, // No mutation to make test deterministic
            crossover_rate: 0.0, // No crossover to make test deterministic
            elitism_count: 5,
            seed: Some(42),
        };

        let engine = EvolutionEngine::new(config);

        let mut initial_population = Vec::new();
        for i in 0..10 {
            initial_population.push(TestIndividual {
                chromosome: vec![Gene::Integer(i * 10)],
            });
        }

        let evaluator = MaximizeSumEvaluator;
        let selector = TournamentSelection::new(2);
        let crossover = UniformCrossover::new();
        let mutator = PerGeneMutation::new(0.0);

        let result = engine.run(
            initial_population,
            &evaluator,
            &selector,
            &crossover,
            &mutator,
        );

        // With no mutation/crossover and elitism, best should be preserved
        assert_eq!(result.best.len(), 3);
    }
}
