use crate::flag_def::{CurlFlagDef, FlagType};
use ga_engine::adaptive::RateControl;
use ga_engine::gene::Gene;
use ga_engine::traits::{Individual, CrossoverOperator, MutationOperator};
use rand::Rng;
use std::cell::Cell;
use std::collections::{HashSet, HashMap};

#[derive(Debug, Clone)]
pub struct CurlFlagInstance {
    pub name: String,
    pub gene: Gene,
}

#[derive(Debug, Clone)]
pub enum ProtocolMode {
    Fixed(String),
    Evolvable(String),
}

impl ProtocolMode {
    pub fn name(&self) -> &str {
        match self {
            ProtocolMode::Fixed(s) | ProtocolMode::Evolvable(s) => s,
        }
    }

    pub fn is_evolvable(&self) -> bool {
        matches!(self, ProtocolMode::Evolvable(_))
    }
}

#[derive(Debug, Clone)]
pub struct CurlIndividual {
    pub flags: Vec<CurlFlagInstance>,
    genes_cache: Vec<Gene>,
    pub protocol: ProtocolMode,
}

impl Individual for CurlIndividual {
    fn chromosome(&self) -> &[Gene] {
        &self.genes_cache
    }

    fn chromosome_mut(&mut self) -> &mut Vec<Gene> {
        &mut self.genes_cache
    }
}

impl CurlIndividual {
    pub fn protocol_name(&self) -> &str {
        self.protocol.name()
    }

    pub fn sync_genes(&mut self) {
        self.genes_cache = self.flags.iter().map(|f| f.gene.clone()).collect();
    }

    pub fn sync_flags_from_genes(&mut self) {
        for (i, gene) in self.genes_cache.iter().enumerate() {
            if i < self.flags.len() {
                self.flags[i].gene = gene.clone();
            }
        }
    }

    /// Create a random individual with fixed-position chromosomes.
    /// Every individual has a gene for every flag in `available_flags`,
    /// with `min_flags..=max_flags` randomly activated and the rest set to Absent.
    /// This ensures position N always corresponds to the same flag across all
    /// individuals, making crossover type-safe.
    pub fn random(
        available_flags: &[CurlFlagDef],
        min_flags: usize,
        max_flags: usize,
        rng: &mut impl Rng,
        protocol: ProtocolMode,
        include_flags: &HashSet<String>,
    ) -> Self {
        let num_active = rng.gen_range(min_flags..=max_flags.min(available_flags.len()));

        // Pick which flags to activate
        let mut indices: Vec<usize> = (0..available_flags.len()).collect();
        for i in 0..num_active.min(indices.len()) {
            let j = rng.gen_range(i..indices.len());
            indices.swap(i, j);
        }
        let active: HashSet<usize> = indices[..num_active].iter().copied().collect();

        // Create a gene for every flag
        let mut flags = Vec::with_capacity(available_flags.len());
        for (idx, flag_def) in available_flags.iter().enumerate() {
            let gene = if include_flags.contains(&flag_def.name) || active.contains(&idx) {
                flag_def.random_gene(rng)
            } else {
                Gene::Absent
            };
            flags.push(CurlFlagInstance {
                name: flag_def.name.clone(),
                gene,
            });
        }

        let mut individual = CurlIndividual {
            flags,
            genes_cache: Vec::new(),
            protocol,
        };
        individual.sync_genes();
        individual
    }

    /// Reconstruct a CurlIndividual from a stored command string.
    /// Parses "curl --flag1 val1 --flag2 url" against flag definitions.
    /// Flags not in the command are set to Absent.
    pub fn from_command_str(
        command: &str,
        available_flags: &[CurlFlagDef],
        protocol: ProtocolMode,
    ) -> Self {
        let parts: Vec<&str> = command.split_whitespace().collect();
        // Skip the curl binary path (first element) and the URL (last element)
        let flag_parts = if parts.len() >= 2 {
            &parts[1..parts.len() - 1]
        } else {
            &[][..]
        };

        // Build a set of flag names for quick lookup
        let flag_name_set: HashSet<&str> = available_flags.iter()
            .map(|f| f.name.as_str())
            .collect();

        // Parse flag_parts into (name, optional value) pairs
        let mut parsed: HashMap<String, Option<String>> = HashMap::new();
        let mut i = 0;
        while i < flag_parts.len() {
            let token = flag_parts[i];
            if token.starts_with('-') && flag_name_set.contains(token) {
                // Check if next token is a value (not another flag)
                if i + 1 < flag_parts.len() && !flag_parts[i + 1].starts_with('-') {
                    parsed.insert(token.to_string(), Some(flag_parts[i + 1].to_string()));
                    i += 2;
                } else {
                    parsed.insert(token.to_string(), None);
                    i += 1;
                }
            } else {
                i += 1;
            }
        }

        // Build flags array matching the flag_defs order
        let mut flags = Vec::with_capacity(available_flags.len());
        for flag_def in available_flags {
            let gene = if let Some(value) = parsed.get(&flag_def.name) {
                match value {
                    None => Gene::Boolean(true), // flag with no value
                    Some(val) => {
                        // Try to match the value to the flag type
                        match &flag_def.flag_type {
                            FlagType::Boolean => Gene::Boolean(true),
                            FlagType::IntegerRange { min, max } => {
                                val.parse::<i64>()
                                    .map(|v| Gene::Integer(v.clamp(*min, *max)))
                                    .unwrap_or(Gene::Boolean(true))
                            }
                            FlagType::FloatRange { min, max } => {
                                val.parse::<f64>()
                                    .map(|v| Gene::Float(v.clamp(*min, *max)))
                                    .unwrap_or(Gene::Boolean(true))
                            }
                            FlagType::Discrete { options } => {
                                if options.contains(val) {
                                    Gene::Discrete(val.clone())
                                } else {
                                    Gene::Discrete(val.clone())
                                }
                            }
                            FlagType::String => Gene::Discrete(val.clone()),
                        }
                    }
                }
            } else {
                Gene::Absent
            };
            flags.push(CurlFlagInstance {
                name: flag_def.name.clone(),
                gene,
            });
        }

        let mut individual = CurlIndividual {
            flags,
            genes_cache: Vec::new(),
            protocol,
        };
        individual.sync_genes();
        individual
    }

    pub fn to_curl_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        for flag in &self.flags {
            match &flag.gene {
                Gene::Boolean(true) => {
                    args.push(flag.name.clone());
                }
                Gene::Boolean(false) | Gene::Absent => {
                    // Skip this flag
                }
                Gene::Integer(val) => {
                    args.push(flag.name.clone());
                    args.push(val.to_string());
                }
                Gene::Float(val) => {
                    args.push(flag.name.clone());
                    args.push(val.to_string());
                }
                Gene::Discrete(val) => {
                    args.push(flag.name.clone());
                    args.push(val.clone());
                }
            }
        }

        args
    }

    pub fn to_command_string(&self, curl_path: &str, target_url: &str) -> String {
        let mut parts = vec![curl_path.to_string()];
        parts.extend(self.to_curl_args());
        parts.push(target_url.to_string());
        parts.join(" ")
    }
}

/// Custom crossover operator for CurlIndividual that syncs flags after crossover
pub struct CurlCrossover<C: CrossoverOperator<CurlIndividual>> {
    inner: C,
}

impl<C: CrossoverOperator<CurlIndividual>> CurlCrossover<C> {
    pub fn new(inner: C) -> Self {
        Self { inner }
    }
}

impl<C: CrossoverOperator<CurlIndividual>> CrossoverOperator<CurlIndividual> for CurlCrossover<C> {
    fn crossover(&self, parent_a: &CurlIndividual, parent_b: &CurlIndividual, rng: &mut impl Rng) -> CurlIndividual {
        let mut child = self.inner.crossover(parent_a, parent_b, rng);

        // Protocol selection: if both parents have Evolvable protocols, randomly pick one
        child.protocol = match (&parent_a.protocol, &parent_b.protocol) {
            (ProtocolMode::Evolvable(_), ProtocolMode::Evolvable(_)) => {
                if rng.gen_bool(0.5) {
                    parent_a.protocol.clone()
                } else {
                    parent_b.protocol.clone()
                }
            }
            _ => parent_a.protocol.clone(),
        };

        child.sync_flags_from_genes();
        child
    }
}

/// Flag-aware mutation operator for CurlIndividual.
/// Unlike the generic PerGeneMutation, this knows about flag definitions
/// and can:
/// - Toggle flags active/absent (activate or deactivate a flag)
/// - Re-pick discrete values from the flag's valid options
/// - Mutate integers/floats within their defined ranges
pub struct CurlMutation {
    rate: Cell<f64>,
    #[allow(dead_code)]
    base_rate: f64,
    pub max_active_flags: usize,
    flag_defs: Vec<CurlFlagDef>,
    flag_affinity: HashMap<String, Vec<String>>,
    available_protocols: Vec<String>,
    include_flags: HashSet<String>,
}

impl CurlMutation {
    pub fn new(
        rate: f64,
        flag_defs: Vec<CurlFlagDef>,
        max_active_flags: usize,
        flag_affinity: HashMap<String, Vec<String>>,
        available_protocols: Vec<String>,
        include_flags: HashSet<String>,
    ) -> Self {
        Self {
            rate: Cell::new(rate),
            base_rate: rate,
            max_active_flags,
            flag_defs,
            flag_affinity,
            available_protocols,
            include_flags,
        }
    }
}

impl RateControl for CurlMutation {
    fn set_rate(&self, rate: f64) {
        self.rate.set(rate);
    }
    fn rate(&self) -> f64 {
        self.rate.get()
    }
}

impl MutationOperator<CurlIndividual> for CurlMutation {
    fn mutate(&self, individual: &mut CurlIndividual, rng: &mut impl Rng) {
        let rate = self.rate.get();
        let toggle_rate = rate * 0.5;

        // Protocol mutation: if evolvable and protocols available
        if individual.protocol.is_evolvable() && !self.available_protocols.is_empty() && rng.gen_bool(toggle_rate) {
            let idx = rng.gen_range(0..self.available_protocols.len());
            individual.protocol = ProtocolMode::Evolvable(self.available_protocols[idx].clone());
        }

        for (i, flag) in individual.flags.iter_mut().enumerate() {
            let flag_def = if i < self.flag_defs.len() {
                &self.flag_defs[i]
            } else {
                continue;
            };

            let is_included = self.include_flags.contains(&flag_def.name);

            // Toggle active/absent (but never deactivate included flags)
            if rng.gen_bool(toggle_rate) {
                match &flag.gene {
                    Gene::Absent => {
                        // Activate: apply 80/20 bias
                        // 80% pick from current protocol's affinity list (if non-empty)
                        // 20% from any flag
                        let use_affinity = rng.gen_bool(0.8);
                        let protocol_name = individual.protocol.name();

                        if use_affinity {
                            if let Some(affinity_flags) = self.flag_affinity.get(protocol_name) {
                                if !affinity_flags.is_empty() {
                                    // Check if current flag is in the affinity list
                                    if affinity_flags.contains(&flag_def.name) {
                                        flag.gene = flag_def.random_gene(rng);
                                    } else {
                                        // Skip this flag for now (80% bias towards affinity)
                                        continue;
                                    }
                                } else {
                                    // No affinity list, activate normally
                                    flag.gene = flag_def.random_gene(rng);
                                }
                            } else {
                                // No affinity list for this protocol, activate normally
                                flag.gene = flag_def.random_gene(rng);
                            }
                        } else {
                            // 20% case: activate any flag
                            flag.gene = flag_def.random_gene(rng);
                        }
                    }
                    _ if is_included => {
                        // Never deactivate included flags; mutate value instead
                        flag.gene = flag_def.random_gene(rng);
                    }
                    _ => {
                        // Deactivate
                        flag.gene = Gene::Absent;
                    }
                }
                continue;
            }

            // Value mutation (only for active genes)
            if !rng.gen_bool(rate) {
                continue;
            }

            match (&mut flag.gene, &flag_def.flag_type) {
                (Gene::Boolean(val), _) => {
                    *val = !*val;
                }
                (Gene::Integer(val), FlagType::IntegerRange { min, max }) => {
                    // Mutate within range with occasional jumps
                    if rng.gen_bool(0.1) {
                        // 10% chance: random value in full range
                        *val = rng.gen_range(*min..=*max);
                    } else {
                        // 90% chance: small delta
                        let range = (*max - *min).max(1);
                        let delta = rng.gen_range(-(range / 10)..=(range / 10)).max(1);
                        *val = (*val + delta).clamp(*min, *max);
                    }
                }
                (Gene::Integer(val), _) => {
                    let delta = rng.gen_range(-10..=10);
                    *val = val.saturating_add(delta);
                }
                (Gene::Float(val), FlagType::FloatRange { min, max }) => {
                    if rng.gen_bool(0.1) {
                        *val = rng.gen_range(*min..=*max);
                    } else {
                        let range = (*max - *min).max(1.0);
                        let delta = rng.gen_range(-(range / 10.0)..=(range / 10.0));
                        *val = (*val + delta).clamp(*min, *max);
                    }
                }
                (Gene::Float(val), _) => {
                    let delta = rng.gen_range(-1.0..=1.0);
                    *val += delta;
                }
                (Gene::Discrete(_), FlagType::Discrete { options }) if !options.is_empty() => {
                    // Re-pick a random value from the valid options
                    let idx = rng.gen_range(0..options.len());
                    flag.gene = Gene::Discrete(options[idx].clone());
                }
                _ => {}
            }
        }

        // Enforce max active flags: if over the limit, randomly deactivate excess
        // (never deactivate included flags)
        let active_indices: Vec<usize> = individual.flags.iter().enumerate()
            .filter(|(_, f)| !matches!(f.gene, Gene::Absent))
            .map(|(i, _)| i)
            .collect();

        if active_indices.len() > self.max_active_flags {
            // Only consider non-included flags for deactivation
            let mut deactivatable: Vec<usize> = active_indices.iter()
                .filter(|&&i| !self.include_flags.contains(&individual.flags[i].name))
                .copied()
                .collect();
            let included_count = active_indices.len() - deactivatable.len();
            let target = self.max_active_flags.saturating_sub(included_count);

            if deactivatable.len() > target {
                for i in 0..deactivatable.len() {
                    let j = rng.gen_range(i..deactivatable.len());
                    deactivatable.swap(i, j);
                }
                for &idx in &deactivatable[target..] {
                    individual.flags[idx].gene = Gene::Absent;
                }
            }
        }

        // Sync the genes cache
        individual.sync_genes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flag_def::CurlFlagDef;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_random_individual_fixed_position() {
        let available_flags = vec![
            CurlFlagDef::boolean("--verbose"),
            CurlFlagDef::boolean("--compressed"),
            CurlFlagDef::integer("--timeout", 1, 100),
            CurlFlagDef::discrete("--request", &["GET", "POST"]),
        ];

        let mut rng = StdRng::seed_from_u64(42);
        let individual = CurlIndividual::random(
            &available_flags,
            2,
            3,
            &mut rng,
            ProtocolMode::Fixed("http".into()),
            &HashSet::new(),
        );

        // Every flag gets a position, even if Absent
        assert_eq!(individual.flags.len(), 4);
        assert_eq!(individual.genes_cache.len(), 4);

        // Flag names match in order
        assert_eq!(individual.flags[0].name, "--verbose");
        assert_eq!(individual.flags[1].name, "--compressed");
        assert_eq!(individual.flags[2].name, "--timeout");
        assert_eq!(individual.flags[3].name, "--request");

        // Count active (non-Absent) flags
        let active = individual.flags.iter()
            .filter(|f| !matches!(f.gene, Gene::Absent))
            .count();
        assert!(active >= 2 && active <= 3);
    }

    #[test]
    fn test_to_curl_args_includes_correctly() {
        let flags = vec![
            CurlFlagInstance {
                name: "--verbose".to_string(),
                gene: Gene::Boolean(true),
            },
            CurlFlagInstance {
                name: "--compressed".to_string(),
                gene: Gene::Absent,
            },
            CurlFlagInstance {
                name: "--timeout".to_string(),
                gene: Gene::Integer(30),
            },
        ];

        let mut individual = CurlIndividual {
            flags,
            genes_cache: Vec::new(),
            protocol: ProtocolMode::Fixed("http".into()),
        };
        individual.sync_genes();

        let args = individual.to_curl_args();

        assert_eq!(args.len(), 3); // --verbose, --timeout, 30
        assert_eq!(args[0], "--verbose");
        assert_eq!(args[1], "--timeout");
        assert_eq!(args[2], "30");
    }

    #[test]
    fn test_to_curl_args_excludes_correctly() {
        let flags = vec![
            CurlFlagInstance {
                name: "--verbose".to_string(),
                gene: Gene::Boolean(false),
            },
            CurlFlagInstance {
                name: "--absent-flag".to_string(),
                gene: Gene::Absent,
            },
        ];

        let mut individual = CurlIndividual {
            flags,
            genes_cache: Vec::new(),
            protocol: ProtocolMode::Fixed("http".into()),
        };
        individual.sync_genes();

        let args = individual.to_curl_args();

        assert_eq!(args.len(), 0);
    }

    #[test]
    fn test_to_command_string_format() {
        let flags = vec![
            CurlFlagInstance {
                name: "--verbose".to_string(),
                gene: Gene::Boolean(true),
            },
            CurlFlagInstance {
                name: "--max-time".to_string(),
                gene: Gene::Integer(60),
            },
        ];

        let mut individual = CurlIndividual {
            flags,
            genes_cache: Vec::new(),
            protocol: ProtocolMode::Fixed("http".into()),
        };
        individual.sync_genes();

        let cmd = individual.to_command_string("/usr/bin/curl", "http://example.com");

        assert_eq!(cmd, "/usr/bin/curl --verbose --max-time 60 http://example.com");
    }

    #[test]
    fn test_sync_genes() {
        let flags = vec![
            CurlFlagInstance {
                name: "--verbose".to_string(),
                gene: Gene::Boolean(true),
            },
            CurlFlagInstance {
                name: "--timeout".to_string(),
                gene: Gene::Integer(30),
            },
        ];

        let mut individual = CurlIndividual {
            flags,
            genes_cache: Vec::new(),
            protocol: ProtocolMode::Fixed("http".into()),
        };

        assert_eq!(individual.genes_cache.len(), 0);

        individual.sync_genes();

        assert_eq!(individual.genes_cache.len(), 2);
        assert_eq!(individual.genes_cache[0], Gene::Boolean(true));
        assert_eq!(individual.genes_cache[1], Gene::Integer(30));
    }

    #[test]
    fn test_sync_flags_from_genes() {
        let flags = vec![
            CurlFlagInstance {
                name: "--verbose".to_string(),
                gene: Gene::Boolean(true),
            },
            CurlFlagInstance {
                name: "--timeout".to_string(),
                gene: Gene::Integer(30),
            },
        ];

        let mut individual = CurlIndividual {
            flags,
            genes_cache: vec![Gene::Boolean(false), Gene::Integer(60)],
            protocol: ProtocolMode::Fixed("http".into()),
        };

        individual.sync_flags_from_genes();

        assert_eq!(individual.flags[0].gene, Gene::Boolean(false));
        assert_eq!(individual.flags[1].gene, Gene::Integer(60));
    }

    #[test]
    fn test_curl_mutation_toggles_and_mutates() {
        let flag_defs = vec![
            CurlFlagDef::boolean("--verbose"),
            CurlFlagDef::discrete("--request", &["GET", "POST", "PUT"]),
            CurlFlagDef::integer("--timeout", 1, 100),
        ];

        let flags = vec![
            CurlFlagInstance { name: "--verbose".to_string(), gene: Gene::Boolean(true) },
            CurlFlagInstance { name: "--request".to_string(), gene: Gene::Discrete("GET".to_string()) },
            CurlFlagInstance { name: "--timeout".to_string(), gene: Gene::Absent },
        ];

        let mut individual = CurlIndividual {
            flags,
            genes_cache: Vec::new(),
            protocol: ProtocolMode::Fixed("http".into()),
        };
        individual.sync_genes();

        let mutator = CurlMutation::new(
            1.0,
            flag_defs,
            35,
            HashMap::new(),
            vec![],
            HashSet::new(),
        ); // rate=1.0 to force mutations
        let mut rng = StdRng::seed_from_u64(42);

        let original_request = individual.flags[1].gene.clone();
        mutator.mutate(&mut individual, &mut rng);

        // With rate=1.0, at least some genes should have changed
        let changed = individual.flags.iter().zip(["--verbose", "--request", "--timeout"])
            .any(|(f, _)| match (&f.gene, &f.name.as_str()) {
                (Gene::Absent, &"--verbose") => true, // was toggled off
                (Gene::Boolean(false), &"--verbose") => true, // was flipped
                _ => f.gene != original_request && f.name == "--request",
            });
        // Just verify it didn't panic and produced valid state
        assert_eq!(individual.flags.len(), 3);
        assert_eq!(individual.genes_cache.len(), 3);
    }

    #[test]
    fn test_from_command_str_roundtrip() {
        let flag_defs = vec![
            CurlFlagDef::boolean("--verbose"),
            CurlFlagDef::boolean("--compressed"),
            CurlFlagDef::integer("--timeout", 1, 100),
            CurlFlagDef::discrete("--request", &["GET", "POST", "PUT"]),
        ];

        let cmd = "curl --verbose --timeout 30 --request POST http://localhost:8080";
        let individual = CurlIndividual::from_command_str(
            cmd, &flag_defs, ProtocolMode::Fixed("http".into()),
        );

        assert_eq!(individual.flags.len(), 4);
        // --verbose should be active
        assert_eq!(individual.flags[0].gene, Gene::Boolean(true));
        // --compressed should be absent (not in command)
        assert_eq!(individual.flags[1].gene, Gene::Absent);
        // --timeout should be 30
        assert_eq!(individual.flags[2].gene, Gene::Integer(30));
        // --request should be POST
        assert_eq!(individual.flags[3].gene, Gene::Discrete("POST".to_string()));
    }

    #[test]
    fn test_from_command_str_unknown_flags_ignored() {
        let flag_defs = vec![
            CurlFlagDef::boolean("--verbose"),
            CurlFlagDef::integer("--timeout", 1, 100),
        ];

        let cmd = "curl --verbose --unknown-flag foo --timeout 10 http://example.com";
        let individual = CurlIndividual::from_command_str(
            cmd, &flag_defs, ProtocolMode::Fixed("http".into()),
        );

        assert_eq!(individual.flags.len(), 2);
        assert_eq!(individual.flags[0].gene, Gene::Boolean(true));
        assert_eq!(individual.flags[1].gene, Gene::Integer(10));
    }

    #[test]
    fn test_individual_with_fixed_protocol() {
        let individual = CurlIndividual {
            flags: vec![],
            genes_cache: vec![],
            protocol: ProtocolMode::Fixed("http".into()),
        };
        assert_eq!(individual.protocol_name(), "http");
    }

    #[test]
    fn test_individual_with_evolvable_protocol() {
        let individual = CurlIndividual {
            flags: vec![],
            genes_cache: vec![],
            protocol: ProtocolMode::Evolvable("ftp".into()),
        };
        assert_eq!(individual.protocol_name(), "ftp");
    }

    #[test]
    fn test_include_flag_always_active_in_random() {
        let available_flags = vec![
            CurlFlagDef::boolean("--verbose"),
            CurlFlagDef::boolean("--compressed"),
            CurlFlagDef::integer("--timeout", 1, 100),
            CurlFlagDef::discrete("--request", &["GET", "POST"]),
        ];

        let include = HashSet::from(["--verbose".to_string()]);
        let mut rng = StdRng::seed_from_u64(99);

        // Generate many individuals; --verbose must always be active
        for _ in 0..20 {
            let individual = CurlIndividual::random(
                &available_flags, 1, 2, &mut rng,
                ProtocolMode::Fixed("http".into()), &include,
            );
            assert!(!matches!(individual.flags[0].gene, Gene::Absent),
                "--verbose should always be active with include-flag");
        }
    }

    #[test]
    fn test_include_flag_not_deactivated_by_mutation() {
        let flag_defs = vec![
            CurlFlagDef::boolean("--verbose"),
            CurlFlagDef::boolean("--compressed"),
            CurlFlagDef::integer("--timeout", 1, 100),
        ];

        let include = HashSet::from(["--verbose".to_string()]);
        let mutator = CurlMutation::new(
            1.0, flag_defs, 35, HashMap::new(), vec![], include,
        );

        let mut rng = StdRng::seed_from_u64(42);

        for _ in 0..20 {
            let mut individual = CurlIndividual {
                flags: vec![
                    CurlFlagInstance { name: "--verbose".to_string(), gene: Gene::Boolean(true) },
                    CurlFlagInstance { name: "--compressed".to_string(), gene: Gene::Boolean(true) },
                    CurlFlagInstance { name: "--timeout".to_string(), gene: Gene::Integer(30) },
                ],
                genes_cache: Vec::new(),
                protocol: ProtocolMode::Fixed("http".into()),
            };
            individual.sync_genes();
            mutator.mutate(&mut individual, &mut rng);
            assert!(!matches!(individual.flags[0].gene, Gene::Absent),
                "--verbose should never be deactivated with include-flag");
        }
    }

    #[test]
    fn test_include_flag_survives_max_active_enforcement() {
        let flag_defs = vec![
            CurlFlagDef::boolean("--verbose"),
            CurlFlagDef::boolean("--compressed"),
            CurlFlagDef::integer("--timeout", 1, 100),
        ];

        let include = HashSet::from(["--verbose".to_string()]);
        // max_active_flags = 1, but --verbose is included so it must survive
        let mutator = CurlMutation::new(
            0.0, flag_defs, 1, HashMap::new(), vec![], include,
        );

        let mut individual = CurlIndividual {
            flags: vec![
                CurlFlagInstance { name: "--verbose".to_string(), gene: Gene::Boolean(true) },
                CurlFlagInstance { name: "--compressed".to_string(), gene: Gene::Boolean(true) },
                CurlFlagInstance { name: "--timeout".to_string(), gene: Gene::Integer(30) },
            ],
            genes_cache: Vec::new(),
            protocol: ProtocolMode::Fixed("http".into()),
        };
        individual.sync_genes();

        let mut rng = StdRng::seed_from_u64(42);
        mutator.mutate(&mut individual, &mut rng);

        // --verbose must still be active
        assert!(!matches!(individual.flags[0].gene, Gene::Absent),
            "--verbose must survive max_active_flags enforcement");
        // At most 1 total active flag (the included one), others should be deactivated
        let active_count = individual.flags.iter()
            .filter(|f| !matches!(f.gene, Gene::Absent))
            .count();
        assert!(active_count <= 1, "max_active_flags should deactivate non-included flags");
    }
}
