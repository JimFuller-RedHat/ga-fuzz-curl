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
    String,
}

#[derive(Debug, Clone)]
pub struct OpenSslFlagDef {
    pub name: std::string::String,
    pub flag_type: FlagType,
    pub arg_hint: Option<std::string::String>,
    #[allow(dead_code)]
    pub description: std::string::String,
}

impl OpenSslFlagDef {
    #[allow(dead_code)]
    pub fn boolean(name: impl Into<std::string::String>) -> Self {
        Self {
            name: name.into(),
            flag_type: FlagType::Boolean,
            arg_hint: None,
            description: std::string::String::new(),
        }
    }

    #[allow(dead_code)]
    pub fn integer(name: impl Into<std::string::String>, min: i64, max: i64) -> Self {
        Self {
            name: name.into(),
            flag_type: FlagType::IntegerRange { min, max },
            arg_hint: None,
            description: std::string::String::new(),
        }
    }

    #[allow(dead_code)]
    pub fn discrete(name: impl Into<std::string::String>, options: &[&str]) -> Self {
        Self {
            name: name.into(),
            flag_type: FlagType::Discrete {
                options: options.iter().map(|s| s.to_string()).collect(),
            },
            arg_hint: None,
            description: std::string::String::new(),
        }
    }

    pub fn random_gene(&self, rng: &mut impl Rng) -> Gene {
        match &self.flag_type {
            FlagType::Boolean => Gene::Boolean(true),
            FlagType::Discrete { options } => {
                if options.is_empty() {
                    Gene::Absent
                } else {
                    let idx = rng.gen_range(0..options.len());
                    Gene::Discrete(options[idx].clone())
                }
            }
            FlagType::IntegerRange { min, max } => {
                Gene::Integer(rng.gen_range(*min..=*max))
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
        let flag = OpenSslFlagDef::boolean("-tls1_2");
        assert_eq!(flag.name, "-tls1_2");
        assert!(matches!(flag.flag_type, FlagType::Boolean));
    }

    #[test]
    fn test_integer_constructor() {
        let flag = OpenSslFlagDef::integer("-verify", 0, 10);
        match flag.flag_type {
            FlagType::IntegerRange { min, max } => {
                assert_eq!(min, 0);
                assert_eq!(max, 10);
            }
            _ => panic!("Expected IntegerRange"),
        }
    }

    #[test]
    fn test_discrete_constructor() {
        let flag = OpenSslFlagDef::discrete("-cipher", &["ALL", "HIGH", "LOW"]);
        match flag.flag_type {
            FlagType::Discrete { options } => {
                assert_eq!(options.len(), 3);
                assert_eq!(options[0], "ALL");
            }
            _ => panic!("Expected Discrete"),
        }
    }

    #[test]
    fn test_random_gene_boolean_always_true() {
        let flag = OpenSslFlagDef::boolean("-debug");
        let mut rng = StdRng::seed_from_u64(42);
        let gene = flag.random_gene(&mut rng);
        assert_eq!(gene, Gene::Boolean(true));
    }

    #[test]
    fn test_random_gene_integer_in_range() {
        let flag = OpenSslFlagDef::integer("-verify", 0, 10);
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..100 {
            match flag.random_gene(&mut rng) {
                Gene::Integer(v) => assert!(v >= 0 && v <= 10),
                _ => panic!("Expected Integer gene"),
            }
        }
    }

    #[test]
    fn test_random_gene_string_is_absent() {
        let flag = OpenSslFlagDef {
            name: "-unknown".into(),
            flag_type: FlagType::String,
            arg_hint: None,
            description: std::string::String::new(),
        };
        let mut rng = StdRng::seed_from_u64(42);
        assert_eq!(flag.random_gene(&mut rng), Gene::Absent);
    }
}
