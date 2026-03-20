use ga_engine::gene::Gene;
use rand::Rng;

#[derive(Debug, Clone)]
pub struct LsFlag {
    pub name: &'static str,
    pub values: FlagValues,
}

#[derive(Debug, Clone)]
pub enum FlagValues {
    /// Boolean flag (present or absent)
    Bool,
    /// Flag takes a value from a discrete set
    Discrete(&'static [&'static str]),
    /// Flag takes a glob pattern
    Pattern,
}

/// All known ls flags
pub fn all_flags() -> Vec<LsFlag> {
    vec![
        LsFlag { name: "-a", values: FlagValues::Bool },
        LsFlag { name: "-A", values: FlagValues::Bool },
        LsFlag { name: "--author", values: FlagValues::Bool },
        LsFlag { name: "-b", values: FlagValues::Bool },
        LsFlag { name: "--block-size", values: FlagValues::Discrete(&["K", "M", "G", "T", "KB", "MB", "1", "1024", "human-readable", "si"]) },
        LsFlag { name: "-B", values: FlagValues::Bool },
        LsFlag { name: "-c", values: FlagValues::Bool },
        LsFlag { name: "-C", values: FlagValues::Bool },
        LsFlag { name: "--color", values: FlagValues::Discrete(&["always", "auto", "never"]) },
        LsFlag { name: "-d", values: FlagValues::Bool },
        LsFlag { name: "-D", values: FlagValues::Bool },
        LsFlag { name: "-f", values: FlagValues::Bool },
        LsFlag { name: "-F", values: FlagValues::Discrete(&["always", "auto", "never"]) },
        LsFlag { name: "--file-type", values: FlagValues::Bool },
        LsFlag { name: "--format", values: FlagValues::Discrete(&["across", "commas", "horizontal", "long", "single-column", "verbose", "vertical"]) },
        LsFlag { name: "--full-time", values: FlagValues::Bool },
        LsFlag { name: "-g", values: FlagValues::Bool },
        LsFlag { name: "--group-directories-first", values: FlagValues::Bool },
        LsFlag { name: "-G", values: FlagValues::Bool },
        LsFlag { name: "-h", values: FlagValues::Bool },
        LsFlag { name: "--si", values: FlagValues::Bool },
        LsFlag { name: "-H", values: FlagValues::Bool },
        LsFlag { name: "--hide", values: FlagValues::Pattern },
        LsFlag { name: "--hyperlink", values: FlagValues::Discrete(&["always", "auto", "never"]) },
        LsFlag { name: "-i", values: FlagValues::Bool },
        LsFlag { name: "-I", values: FlagValues::Pattern },
        LsFlag { name: "-k", values: FlagValues::Bool },
        LsFlag { name: "-l", values: FlagValues::Bool },
        LsFlag { name: "-L", values: FlagValues::Bool },
        LsFlag { name: "-m", values: FlagValues::Bool },
        LsFlag { name: "-n", values: FlagValues::Bool },
        LsFlag { name: "-N", values: FlagValues::Bool },
        LsFlag { name: "-o", values: FlagValues::Bool },
        LsFlag { name: "-p", values: FlagValues::Bool },
        LsFlag { name: "-q", values: FlagValues::Bool },
        LsFlag { name: "--show-control-chars", values: FlagValues::Bool },
        LsFlag { name: "-Q", values: FlagValues::Bool },
        LsFlag { name: "--quoting-style", values: FlagValues::Discrete(&["literal", "locale", "shell", "shell-always", "shell-escape", "shell-escape-always", "c", "escape"]) },
        LsFlag { name: "-r", values: FlagValues::Bool },
        LsFlag { name: "-R", values: FlagValues::Bool },
        LsFlag { name: "-s", values: FlagValues::Bool },
        LsFlag { name: "-S", values: FlagValues::Bool },
        LsFlag { name: "--sort", values: FlagValues::Discrete(&["none", "size", "time", "version", "extension", "width"]) },
        LsFlag { name: "--time", values: FlagValues::Discrete(&["atime", "access", "use", "ctime", "status", "birth", "creation", "modification"]) },
        LsFlag { name: "--time-style", values: FlagValues::Discrete(&["full-iso", "long-iso", "iso", "locale", "+%Y-%m-%d"]) },
        LsFlag { name: "-t", values: FlagValues::Bool },
        LsFlag { name: "-T", values: FlagValues::Discrete(&["2", "4", "8", "16"]) },
        LsFlag { name: "-u", values: FlagValues::Bool },
        LsFlag { name: "-U", values: FlagValues::Bool },
        LsFlag { name: "-v", values: FlagValues::Bool },
        LsFlag { name: "-w", values: FlagValues::Discrete(&["20", "40", "80", "120", "200", "1000"]) },
        LsFlag { name: "-x", values: FlagValues::Bool },
        LsFlag { name: "-X", values: FlagValues::Bool },
        LsFlag { name: "-Z", values: FlagValues::Bool },
        LsFlag { name: "-1", values: FlagValues::Bool },
    ]
}

/// Generate a random Gene value for a flag
pub fn random_gene(flag: &LsFlag, rng: &mut impl Rng) -> Gene {
    match &flag.values {
        FlagValues::Bool => Gene::Boolean(true),
        FlagValues::Discrete(options) => {
            let idx = rng.gen_range(0..options.len());
            Gene::Discrete(options[idx].to_string())
        }
        FlagValues::Pattern => {
            let patterns = &["*", ".*", "*.bak", "*.tmp", "[a-z]*", "?", "*.o"];
            let idx = rng.gen_range(0..patterns.len());
            Gene::Discrete(patterns[idx].to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_all_flags_non_empty() {
        let flags = all_flags();
        assert!(flags.len() > 40);
    }

    #[test]
    fn test_random_gene_bool() {
        let flag = LsFlag { name: "-a", values: FlagValues::Bool };
        let mut rng = StdRng::seed_from_u64(42);
        let gene = random_gene(&flag, &mut rng);
        assert_eq!(gene, Gene::Boolean(true));
    }

    #[test]
    fn test_random_gene_discrete() {
        let flag = LsFlag { name: "--color", values: FlagValues::Discrete(&["always", "auto", "never"]) };
        let mut rng = StdRng::seed_from_u64(42);
        let gene = random_gene(&flag, &mut rng);
        matches!(gene, Gene::Discrete(_));
    }
}
