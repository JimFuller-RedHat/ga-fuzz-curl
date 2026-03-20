use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Gene {
    Boolean(bool),
    Discrete(String),
    Integer(i64),
    Float(f64),
    Absent,
}

impl fmt::Display for Gene {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Gene::Boolean(b) => write!(f, "{}", b),
            Gene::Discrete(s) => write!(f, "{}", s),
            Gene::Integer(i) => write!(f, "{}", i),
            Gene::Float(fl) => write!(f, "{}", fl),
            Gene::Absent => write!(f, "Absent"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boolean_variant() {
        let gene = Gene::Boolean(true);
        assert_eq!(gene, Gene::Boolean(true));
        assert_ne!(gene, Gene::Boolean(false));
    }

    #[test]
    fn test_discrete_variant() {
        let gene = Gene::Discrete("GET".to_string());
        assert_eq!(gene, Gene::Discrete("GET".to_string()));
        assert_ne!(gene, Gene::Discrete("POST".to_string()));
    }

    #[test]
    fn test_integer_variant() {
        let gene = Gene::Integer(42);
        assert_eq!(gene, Gene::Integer(42));
        assert_ne!(gene, Gene::Integer(100));
    }

    #[test]
    fn test_float_variant() {
        let gene = Gene::Float(3.14);
        assert_eq!(gene, Gene::Float(3.14));
        assert_ne!(gene, Gene::Float(2.71));
    }

    #[test]
    fn test_absent_variant() {
        let gene = Gene::Absent;
        assert_eq!(gene, Gene::Absent);
    }

    #[test]
    fn test_clone() {
        let gene = Gene::Integer(42);
        let cloned = gene.clone();
        assert_eq!(gene, cloned);
    }

    #[test]
    fn test_display_boolean() {
        assert_eq!(Gene::Boolean(true).to_string(), "true");
        assert_eq!(Gene::Boolean(false).to_string(), "false");
    }

    #[test]
    fn test_display_discrete() {
        assert_eq!(Gene::Discrete("GET".to_string()).to_string(), "GET");
    }

    #[test]
    fn test_display_integer() {
        assert_eq!(Gene::Integer(42).to_string(), "42");
    }

    #[test]
    fn test_display_float() {
        assert_eq!(Gene::Float(3.14).to_string(), "3.14");
    }

    #[test]
    fn test_display_absent() {
        assert_eq!(Gene::Absent.to_string(), "Absent");
    }
}
