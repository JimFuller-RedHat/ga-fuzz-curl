use crate::fitness::FitnessScore;
use crate::gene::Gene;
use rand::Rng;

pub trait Individual: Clone + Send + Sync {
    fn chromosome(&self) -> &[Gene];
    fn chromosome_mut(&mut self) -> &mut Vec<Gene>;
}

pub trait FitnessEvaluator<I: Individual>: Sync {
    fn evaluate(&self, individual: &I) -> FitnessScore;
}

pub trait CrossoverOperator<I: Individual> {
    fn crossover(&self, parent_a: &I, parent_b: &I, rng: &mut impl Rng) -> I;
}

pub trait MutationOperator<I: Individual> {
    fn mutate(&self, individual: &mut I, rng: &mut impl Rng);
}

pub trait SelectionStrategy<I: Individual> {
    fn select<'a>(&self, population: &'a [Scored<I>], rng: &mut impl Rng) -> &'a I;
}

#[derive(Debug, Clone)]
pub struct Scored<I: Individual> {
    pub individual: I,
    pub fitness: FitnessScore,
}

impl<I: Individual> Scored<I> {
    pub fn new(individual: I, fitness: FitnessScore) -> Self {
        Self { individual, fitness }
    }
}
