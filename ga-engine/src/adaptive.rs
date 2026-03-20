/// Adaptive mutation rate with stagnation detection.
///
/// Tracks the all-time best fitness. When no new all-time best has been
/// achieved in `stagnation_window` generations, spikes the mutation rate
/// to escape local optima ("hypermutation"). After spiking, decays back
/// to the base rate over several generations.

/// Configuration for adaptive mutation
#[derive(Debug, Clone)]
pub struct AdaptiveMutationConfig {
    /// Base mutation rate (what we return to after a spike)
    pub base_rate: f64,
    /// Maximum mutation rate during a spike
    pub max_rate: f64,
    /// Number of generations without a new all-time best before triggering a spike
    pub stagnation_window: usize,
    /// How many generations a spike lasts before decaying
    pub spike_duration: usize,
}

impl Default for AdaptiveMutationConfig {
    fn default() -> Self {
        Self {
            base_rate: 0.05,
            max_rate: 0.25,
            stagnation_window: 20,
            spike_duration: 3,
        }
    }
}

/// Tracks fitness history and computes the current adaptive mutation rate
pub struct AdaptiveMutationRate {
    config: AdaptiveMutationConfig,
    all_time_best: f64,
    generations_since_improvement: usize,
    current_rate: f64,
    spike_remaining: usize,
    total_spikes: usize,
}

impl AdaptiveMutationRate {
    pub fn new(config: AdaptiveMutationConfig) -> Self {
        let current_rate = config.base_rate;
        Self {
            config,
            all_time_best: f64::NEG_INFINITY,
            generations_since_improvement: 0,
            current_rate,
            spike_remaining: 0,
            total_spikes: 0,
        }
    }

    /// Record the best fitness for this generation and return the mutation rate
    /// to use for the next generation.
    pub fn update(&mut self, best_fitness: f64) -> f64 {
        // If we're in a spike, count it down and decay
        if self.spike_remaining > 0 {
            self.spike_remaining -= 1;
            if self.spike_remaining == 0 {
                self.current_rate = self.config.base_rate;
            } else {
                let progress = self.spike_remaining as f64 / self.config.spike_duration as f64;
                self.current_rate = self.config.base_rate
                    + (self.config.max_rate - self.config.base_rate) * progress;
            }
            // Still track improvements during spike
            if best_fitness > self.all_time_best {
                self.all_time_best = best_fitness;
                self.generations_since_improvement = 0;
            } else {
                self.generations_since_improvement += 1;
            }
            return self.current_rate;
        }

        // Check if we have a new all-time best
        if best_fitness > self.all_time_best {
            self.all_time_best = best_fitness;
            self.generations_since_improvement = 0;
        } else {
            self.generations_since_improvement += 1;
        }

        // Trigger spike if no new all-time best in stagnation_window generations
        if self.generations_since_improvement >= self.config.stagnation_window {
            self.spike_remaining = self.config.spike_duration;
            self.current_rate = self.config.max_rate;
            self.total_spikes += 1;
            self.generations_since_improvement = 0; // reset counter
        }

        self.current_rate
    }

    /// Current mutation rate
    pub fn rate(&self) -> f64 {
        self.current_rate
    }

    /// Whether we're currently in a hypermutation spike
    pub fn is_spiking(&self) -> bool {
        self.spike_remaining > 0
    }

    /// Total number of spikes triggered so far
    pub fn total_spikes(&self) -> usize {
        self.total_spikes
    }
}

/// Trait for mutation operators that support dynamic rate adjustment
pub trait RateControl {
    fn set_rate(&self, rate: f64);
    fn rate(&self) -> f64;
}

/// Configuration for diversity-based random immigrant injection
#[derive(Debug, Clone)]
pub struct DiversityConfig {
    /// Minimum diversity ratio (0.0-1.0). Below this, immigrants are injected.
    /// Diversity = unique activation patterns / population size.
    pub min_diversity: f64,
    /// Fraction of population to replace with immigrants when diversity is low (0.0-1.0)
    pub immigrant_fraction: f64,
}

impl Default for DiversityConfig {
    fn default() -> Self {
        Self {
            min_diversity: 0.15,
            immigrant_fraction: 0.05,
        }
    }
}

/// Measure population diversity as the ratio of unique flag activation patterns.
/// Returns a value between 0.0 (all identical) and 1.0 (all unique).
pub fn measure_diversity<I: crate::traits::Individual>(population: &[I]) -> f64 {
    if population.is_empty() {
        return 0.0;
    }
    use std::collections::HashSet;
    let patterns: HashSet<Vec<bool>> = population
        .iter()
        .map(|ind| {
            ind.chromosome()
                .iter()
                .map(|g| !matches!(g, crate::gene::Gene::Absent))
                .collect()
        })
        .collect();
    patterns.len() as f64 / population.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_spike_with_improving_fitness() {
        let config = AdaptiveMutationConfig {
            base_rate: 0.05,
            max_rate: 0.25,
            stagnation_window: 3,
            spike_duration: 2,
        };
        let mut adaptive = AdaptiveMutationRate::new(config);

        // Steadily improving fitness — each gen sets a new all-time best
        for i in 0..10 {
            let rate = adaptive.update(10.0 + i as f64 * 2.0);
            assert!((rate - 0.05).abs() < 0.001, "Rate should stay at base when improving, got {}", rate);
        }
        assert_eq!(adaptive.total_spikes(), 0);
    }

    #[test]
    fn test_spike_on_stagnation() {
        let config = AdaptiveMutationConfig {
            base_rate: 0.05,
            max_rate: 0.25,
            stagnation_window: 3,
            spike_duration: 2,
        };
        let mut adaptive = AdaptiveMutationRate::new(config);

        // Set an all-time best, then stagnate for 3 generations
        adaptive.update(10.0); // new all-time best
        adaptive.update(8.0);  // no new best, count=1
        adaptive.update(9.0);  // no new best, count=2
        let rate = adaptive.update(7.0); // no new best, count=3 → triggers spike
        assert!(rate > 0.05, "Rate should spike on stagnation, got {}", rate);
        assert!(adaptive.is_spiking());
        assert_eq!(adaptive.total_spikes(), 1);
    }

    #[test]
    fn test_no_spike_with_oscillating_but_improving() {
        let config = AdaptiveMutationConfig {
            base_rate: 0.05,
            max_rate: 0.25,
            stagnation_window: 5,
            spike_duration: 2,
        };
        let mut adaptive = AdaptiveMutationRate::new(config);

        // Fitness oscillates but periodically sets new all-time bests
        adaptive.update(10.0); // new ATB
        adaptive.update(8.0);
        adaptive.update(7.0);
        adaptive.update(11.0); // new ATB — resets counter
        adaptive.update(9.0);
        adaptive.update(8.0);
        adaptive.update(12.0); // new ATB — resets counter
        assert_eq!(adaptive.total_spikes(), 0, "Should not spike when new ATBs keep appearing");
    }

    #[test]
    fn test_spike_decays_to_base() {
        let config = AdaptiveMutationConfig {
            base_rate: 0.05,
            max_rate: 0.25,
            stagnation_window: 3,
            spike_duration: 2,
        };
        let mut adaptive = AdaptiveMutationRate::new(config);

        // Trigger stagnation
        adaptive.update(10.0);
        adaptive.update(10.0);
        adaptive.update(10.0);
        adaptive.update(10.0); // triggers spike (3 gens without new ATB)

        // During spike — decaying
        let rate1 = adaptive.update(10.0);
        assert!(rate1 > 0.05 && rate1 < 0.25, "Should be decaying, got {}", rate1);

        // Spike ends
        let rate2 = adaptive.update(10.0);
        assert!((rate2 - 0.05).abs() < 0.001, "Should return to base, got {}", rate2);
        assert!(!adaptive.is_spiking());
    }

    #[test]
    fn test_multiple_spikes() {
        let config = AdaptiveMutationConfig {
            base_rate: 0.05,
            max_rate: 0.25,
            stagnation_window: 3,
            spike_duration: 1,
        };
        let mut adaptive = AdaptiveMutationRate::new(config);

        // First stagnation
        adaptive.update(10.0); // new ATB
        adaptive.update(10.0);
        adaptive.update(10.0);
        adaptive.update(10.0); // triggers spike #1
        assert_eq!(adaptive.total_spikes(), 1);

        // Spike decays (duration=1), then break out with new ATB
        adaptive.update(20.0); // new ATB
        adaptive.update(30.0); // new ATB
        adaptive.update(40.0); // new ATB

        // Second stagnation at the new plateau
        adaptive.update(40.0);
        adaptive.update(40.0);
        adaptive.update(40.0); // triggers spike #2
        assert!(adaptive.total_spikes() >= 2);
    }

    #[test]
    fn test_improvement_during_spike_resets_counter() {
        let config = AdaptiveMutationConfig {
            base_rate: 0.05,
            max_rate: 0.25,
            stagnation_window: 3,
            spike_duration: 2,
        };
        let mut adaptive = AdaptiveMutationRate::new(config);

        // Trigger first spike
        adaptive.update(10.0);
        adaptive.update(10.0);
        adaptive.update(10.0);
        adaptive.update(10.0); // spike triggered
        assert_eq!(adaptive.total_spikes(), 1);

        // New ATB during spike should reset the stagnation counter
        adaptive.update(15.0); // new ATB during spike
        adaptive.update(12.0); // spike ends, counter reset to 0

        // Should need a full window again to spike
        adaptive.update(13.0); // count=1
        adaptive.update(14.0); // count=2
        let rate = adaptive.update(14.0); // count=3 → spike again
        assert!(rate > 0.05, "Should spike after full window without new ATB");
    }

    #[test]
    fn test_zero_fitness_stagnation() {
        let config = AdaptiveMutationConfig {
            base_rate: 0.05,
            max_rate: 0.30,
            stagnation_window: 3,
            spike_duration: 2,
        };
        let mut adaptive = AdaptiveMutationRate::new(config);

        // All zero fitness — first is ATB (0 > -inf), then stagnates
        adaptive.update(0.0); // new ATB (0.0)
        adaptive.update(0.0); // count=1
        adaptive.update(0.0); // count=2
        let rate = adaptive.update(0.0); // count=3 → spike
        assert!(rate > 0.05, "Should spike when stuck at zero");
    }

    // Diversity tests

    use crate::gene::Gene;
    use crate::traits::Individual;

    #[derive(Debug, Clone)]
    struct TestInd {
        genes: Vec<Gene>,
    }
    impl Individual for TestInd {
        fn chromosome(&self) -> &[Gene] { &self.genes }
        fn chromosome_mut(&mut self) -> &mut Vec<Gene> { &mut self.genes }
    }

    #[test]
    fn test_diversity_all_unique() {
        let pop = vec![
            TestInd { genes: vec![Gene::Boolean(true), Gene::Absent] },
            TestInd { genes: vec![Gene::Absent, Gene::Boolean(true)] },
            TestInd { genes: vec![Gene::Boolean(true), Gene::Boolean(true)] },
        ];
        let d = measure_diversity(&pop);
        assert!((d - 1.0).abs() < 0.01, "All unique should be 1.0, got {}", d);
    }

    #[test]
    fn test_diversity_all_identical() {
        let pop = vec![
            TestInd { genes: vec![Gene::Boolean(true), Gene::Absent] },
            TestInd { genes: vec![Gene::Integer(5), Gene::Absent] }, // same activation pattern
            TestInd { genes: vec![Gene::Discrete("x".into()), Gene::Absent] },
        ];
        let d = measure_diversity(&pop);
        // All have same activation pattern: [true, false]
        assert!((d - 1.0 / 3.0).abs() < 0.01, "Same pattern should be 0.33, got {}", d);
    }

    #[test]
    fn test_diversity_empty() {
        let pop: Vec<TestInd> = vec![];
        assert_eq!(measure_diversity(&pop), 0.0);
    }

    #[test]
    fn test_diversity_config_defaults() {
        let config = DiversityConfig::default();
        assert_eq!(config.min_diversity, 0.15);
        assert_eq!(config.immigrant_fraction, 0.05);
    }
}
