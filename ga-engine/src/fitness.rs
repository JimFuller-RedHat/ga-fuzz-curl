use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct FitnessScore {
    pub total: f64,
    pub components: HashMap<String, f64>,
    /// String metadata that doesn't affect fitness but should travel with the score
    pub metadata: HashMap<String, String>,
}

impl FitnessScore {
    pub fn new(total: f64) -> Self {
        Self {
            total,
            components: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_component(mut self, name: &str, value: f64) -> Self {
        self.components.insert(name.to_string(), value);
        self
    }

    pub fn from_weighted(components: &[(&str, f64)]) -> Self {
        let mut map = HashMap::new();
        let mut total = 0.0;

        for (name, value) in components {
            map.insert(name.to_string(), *value);
            total += value;
        }

        Self {
            total,
            components: map,
            metadata: HashMap::new(),
        }
    }
}

impl PartialOrd for FitnessScore {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.total.partial_cmp(&other.total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let score = FitnessScore::new(100.0);
        assert_eq!(score.total, 100.0);
        assert!(score.components.is_empty());
    }

    #[test]
    fn test_with_component() {
        let score = FitnessScore::new(100.0)
            .with_component("speed", 50.0)
            .with_component("accuracy", 50.0);

        assert_eq!(score.total, 100.0);
        assert_eq!(score.components.len(), 2);
        assert_eq!(score.components.get("speed"), Some(&50.0));
        assert_eq!(score.components.get("accuracy"), Some(&50.0));
    }

    #[test]
    fn test_from_weighted() {
        let score = FitnessScore::from_weighted(&[
            ("speed", 30.0),
            ("accuracy", 40.0),
            ("efficiency", 30.0),
        ]);

        assert_eq!(score.total, 100.0);
        assert_eq!(score.components.len(), 3);
        assert_eq!(score.components.get("speed"), Some(&30.0));
        assert_eq!(score.components.get("accuracy"), Some(&40.0));
        assert_eq!(score.components.get("efficiency"), Some(&30.0));
    }

    #[test]
    fn test_ordering_greater() {
        let score1 = FitnessScore::new(100.0);
        let score2 = FitnessScore::new(50.0);
        assert!(score1 > score2);
    }

    #[test]
    fn test_ordering_less() {
        let score1 = FitnessScore::new(50.0);
        let score2 = FitnessScore::new(100.0);
        assert!(score1 < score2);
    }

    #[test]
    fn test_ordering_equal() {
        let score1 = FitnessScore::new(100.0);
        let score2 = FitnessScore::new(100.0);
        assert_eq!(score1, score2);
    }
}
