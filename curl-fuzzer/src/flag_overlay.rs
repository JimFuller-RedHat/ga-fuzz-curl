use crate::flag_def::{CurlFlagDef, FlagType};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Deserialize)]
struct OverlayConfig {
    flags: Vec<FlagOverlay>,
}

#[derive(Debug, Deserialize)]
struct FlagOverlay {
    name: String,
    #[serde(flatten)]
    flag_type: FlagType,
}

pub fn parse_overlay(toml_str: &str) -> Result<HashMap<String, FlagType>> {
    let config: OverlayConfig = toml::from_str(toml_str)
        .context("Failed to parse TOML overlay")?;

    let mut map = HashMap::new();
    for flag in config.flags {
        map.insert(flag.name, flag.flag_type);
    }

    Ok(map)
}

pub fn parse_flag_affinity(toml_str: &str) -> Result<std::collections::HashMap<String, Vec<String>>> {
    let parsed: toml::Value = toml::from_str(toml_str)?;
    let mut affinity = std::collections::HashMap::new();

    if let Some(table) = parsed.get("flag-affinity").and_then(|v| v.as_table()) {
        for (protocol, value) in table {
            if let Some(flags) = value.get("flags").and_then(|v| v.as_array()) {
                let flag_list: Vec<String> = flags.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                affinity.insert(protocol.clone(), flag_list);
            }
        }
    }

    Ok(affinity)
}

pub fn load_overlay(path: &str) -> Result<HashMap<String, FlagType>> {
    let content = fs::read_to_string(path)
        .context(format!("Failed to read overlay file: {}", path))?;

    parse_overlay(&content)
}

pub fn apply_overlay(flags: &mut [CurlFlagDef], overlay: &HashMap<String, FlagType>) {
    for flag in flags.iter_mut() {
        if let Some(new_type) = overlay.get(&flag.name) {
            flag.flag_type = new_type.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_overlay_with_integer() {
        let toml = r#"
[[flags]]
name = "--connect-timeout"
type = "integer"
min = 1
max = 300
"#;
        let overlay = parse_overlay(toml).expect("Should parse TOML");

        assert_eq!(overlay.len(), 1);
        let flag_type = overlay.get("--connect-timeout").expect("Should have flag");
        match flag_type {
            FlagType::IntegerRange { min, max } => {
                assert_eq!(*min, 1);
                assert_eq!(*max, 300);
            }
            _ => panic!("Expected IntegerRange"),
        }
    }

    #[test]
    fn test_parse_overlay_with_discrete() {
        let toml = r#"
[[flags]]
name = "--cert-type"
type = "discrete"
options = ["PEM", "DER", "ENG"]
"#;
        let overlay = parse_overlay(toml).expect("Should parse TOML");

        assert_eq!(overlay.len(), 1);
        let flag_type = overlay.get("--cert-type").expect("Should have flag");
        match flag_type {
            FlagType::Discrete { options } => {
                assert_eq!(options.len(), 3);
                assert_eq!(options[0], "PEM");
                assert_eq!(options[1], "DER");
                assert_eq!(options[2], "ENG");
            }
            _ => panic!("Expected Discrete"),
        }
    }

    #[test]
    fn test_parse_overlay_with_float() {
        let toml = r#"
[[flags]]
name = "--limit-rate"
type = "float"
min = 0.0
max = 1000.0
"#;
        let overlay = parse_overlay(toml).expect("Should parse TOML");

        assert_eq!(overlay.len(), 1);
        let flag_type = overlay.get("--limit-rate").expect("Should have flag");
        match flag_type {
            FlagType::FloatRange { min, max } => {
                assert_eq!(*min, 0.0);
                assert_eq!(*max, 1000.0);
            }
            _ => panic!("Expected FloatRange"),
        }
    }

    #[test]
    fn test_apply_overlay_changes_flag_type() {
        let mut flags = vec![
            CurlFlagDef::boolean("--verbose"),
            CurlFlagDef {
                name: "--connect-timeout".to_string(),
                flag_type: FlagType::String,
                arg_hint: None,
                description: String::new(),
                requires: Vec::new(),
            },
        ];

        let mut overlay = HashMap::new();
        overlay.insert(
            "--connect-timeout".to_string(),
            FlagType::IntegerRange { min: 1, max: 300 },
        );

        apply_overlay(&mut flags, &overlay);

        // --verbose should remain Boolean
        match &flags[0].flag_type {
            FlagType::Boolean => {}
            _ => panic!("Expected Boolean"),
        }

        // --connect-timeout should be changed to IntegerRange
        match &flags[1].flag_type {
            FlagType::IntegerRange { min, max } => {
                assert_eq!(*min, 1);
                assert_eq!(*max, 300);
            }
            _ => panic!("Expected IntegerRange"),
        }
    }

    #[test]
    fn test_parse_flag_affinity() {
        let toml_str = r#"
            [flag-affinity.ftp]
            flags = ["--ftp-pasv", "--ftp-port"]

            [flag-affinity.smtp]
            flags = ["--mail-from", "--mail-rcpt"]
        "#;

        let affinity = parse_flag_affinity(toml_str).unwrap();
        assert_eq!(affinity.get("ftp").unwrap(), &vec!["--ftp-pasv".to_string(), "--ftp-port".to_string()]);
        assert_eq!(affinity.get("smtp").unwrap().len(), 2);
    }

    #[test]
    fn test_parse_flag_affinity_empty() {
        let toml_str = r#"
            [[flags]]
            name = "--verbose"
            type = "boolean"
        "#;

        let affinity = parse_flag_affinity(toml_str).unwrap();
        assert!(affinity.is_empty());
    }

    #[test]
    fn test_apply_overlay_leaves_unknown_flags_alone() {
        let mut flags = vec![
            CurlFlagDef::boolean("--verbose"),
            CurlFlagDef::boolean("--compressed"),
        ];

        let mut overlay = HashMap::new();
        overlay.insert(
            "--unknown-flag".to_string(),
            FlagType::IntegerRange { min: 1, max: 100 },
        );

        apply_overlay(&mut flags, &overlay);

        // Both flags should remain Boolean
        match &flags[0].flag_type {
            FlagType::Boolean => {}
            _ => panic!("Expected Boolean"),
        }
        match &flags[1].flag_type {
            FlagType::Boolean => {}
            _ => panic!("Expected Boolean"),
        }
    }
}
