use ga_engine::gene::Gene;
use rand::Rng;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum FlagType {
    Boolean,
    Discrete { options: Vec<String> },
    #[serde(rename = "integer")]
    IntegerRange { min: i64, max: i64 },
    #[serde(rename = "float")]
    FloatRange { min: f64, max: f64 },
    String,
}

#[derive(Debug, Clone)]
pub struct CurlFlagDef {
    pub name: String,
    pub flag_type: FlagType,
    pub arg_hint: Option<String>, // e.g. "file", "seconds", "URL" from curl --help
    #[allow(dead_code)]
    pub description: String,
    #[allow(dead_code)]
    pub requires: Vec<String>,
}

impl CurlFlagDef {
    #[allow(dead_code)]
    pub fn boolean(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            flag_type: FlagType::Boolean,
            arg_hint: None,
            description: String::new(),
            requires: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn integer(name: impl Into<String>, min: i64, max: i64) -> Self {
        Self {
            name: name.into(),
            flag_type: FlagType::IntegerRange { min, max },
            arg_hint: None,
            description: String::new(),
            requires: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn float(name: impl Into<String>, min: f64, max: f64) -> Self {
        Self {
            name: name.into(),
            flag_type: FlagType::FloatRange { min, max },
            arg_hint: None,
            description: String::new(),
            requires: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn discrete(name: impl Into<String>, options: &[&str]) -> Self {
        Self {
            name: name.into(),
            flag_type: FlagType::Discrete {
                options: options.iter().map(|s| s.to_string()).collect(),
            },
            arg_hint: None,
            description: String::new(),
            requires: Vec::new(),
        }
    }

    pub fn random_gene(&self, rng: &mut impl Rng) -> Gene {
        match &self.flag_type {
            FlagType::Boolean => Gene::Boolean(rng.gen_bool(0.5)),
            FlagType::Discrete { options } => {
                if options.is_empty() {
                    Gene::Absent
                } else {
                    let idx = rng.gen_range(0..options.len());
                    Gene::Discrete(options[idx].clone())
                }
            }
            FlagType::IntegerRange { min, max } => {
                // 30% chance: pick a boundary/interesting value
                // 70% chance: uniform random in range
                if rng.gen_bool(0.3) {
                    let boundaries: Vec<i64> = [
                        *min, *max, 0, 1, -1,
                        min.saturating_add(1), max.saturating_sub(1),
                        *max / 2,  // midpoint
                    ]
                    .iter()
                    .copied()
                    .filter(|v| *v >= *min && *v <= *max)
                    .collect();
                    if boundaries.is_empty() {
                        Gene::Integer(rng.gen_range(*min..=*max))
                    } else {
                        Gene::Integer(boundaries[rng.gen_range(0..boundaries.len())])
                    }
                } else {
                    Gene::Integer(rng.gen_range(*min..=*max))
                }
            }
            FlagType::FloatRange { min, max } => {
                if rng.gen_bool(0.3) {
                    let boundaries = [*min, *max, 0.0, 1.0, (*min + *max) / 2.0];
                    let valid: Vec<f64> = boundaries.iter()
                        .copied()
                        .filter(|v| *v >= *min && *v <= *max)
                        .collect();
                    if valid.is_empty() {
                        Gene::Float(rng.gen_range(*min..=*max))
                    } else {
                        Gene::Float(valid[rng.gen_range(0..valid.len())])
                    }
                } else {
                    Gene::Float(rng.gen_range(*min..=*max))
                }
            }
            FlagType::String => Gene::Absent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_boolean_constructor() {
        let flag = CurlFlagDef::boolean("--verbose");
        assert_eq!(flag.name, "--verbose");
        match flag.flag_type {
            FlagType::Boolean => {}
            _ => panic!("Expected Boolean flag type"),
        }
    }

    #[test]
    fn test_integer_constructor() {
        let flag = CurlFlagDef::integer("--timeout", 1, 300);
        assert_eq!(flag.name, "--timeout");
        match flag.flag_type {
            FlagType::IntegerRange { min, max } => {
                assert_eq!(min, 1);
                assert_eq!(max, 300);
            }
            _ => panic!("Expected IntegerRange flag type"),
        }
    }

    #[test]
    fn test_discrete_constructor() {
        let flag = CurlFlagDef::discrete("--request", &["GET", "POST", "PUT"]);
        assert_eq!(flag.name, "--request");
        match flag.flag_type {
            FlagType::Discrete { options } => {
                assert_eq!(options.len(), 3);
                assert_eq!(options[0], "GET");
                assert_eq!(options[1], "POST");
                assert_eq!(options[2], "PUT");
            }
            _ => panic!("Expected Discrete flag type"),
        }
    }

    #[test]
    fn test_random_gene_integer_in_range() {
        let flag = CurlFlagDef::integer("--timeout", 10, 20);
        let mut rng = StdRng::seed_from_u64(42);

        for _ in 0..100 {
            let gene = flag.random_gene(&mut rng);
            match gene {
                Gene::Integer(val) => {
                    assert!(val >= 10 && val <= 20, "Value {} out of range [10, 20]", val);
                }
                _ => panic!("Expected Integer gene"),
            }
        }
    }
}
