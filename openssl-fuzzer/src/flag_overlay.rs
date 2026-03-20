use crate::flag_def::{OpenSslFlagDef, FlagType};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use serde::Deserialize;

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

pub fn load_overlay(path: &str) -> Result<HashMap<String, FlagType>> {
    let content = fs::read_to_string(path)
        .context(format!("Failed to read overlay file: {}", path))?;
    parse_overlay(&content)
}

pub fn apply_overlay(flags: &mut [OpenSslFlagDef], overlay: &HashMap<String, FlagType>) {
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
    fn test_parse_overlay_integer() {
        let toml = r#"
[[flags]]
name = "-verify"
type = "integer"
min = 0
max = 10
"#;
        let overlay = parse_overlay(toml).unwrap();
        match overlay.get("-verify").unwrap() {
            FlagType::IntegerRange { min, max } => {
                assert_eq!(*min, 0);
                assert_eq!(*max, 10);
            }
            _ => panic!("Expected IntegerRange"),
        }
    }

    #[test]
    fn test_parse_overlay_discrete() {
        let toml = r#"
[[flags]]
name = "-cipher"
type = "discrete"
options = ["ALL", "HIGH", "LOW"]
"#;
        let overlay = parse_overlay(toml).unwrap();
        match overlay.get("-cipher").unwrap() {
            FlagType::Discrete { options } => {
                assert_eq!(options, &["ALL", "HIGH", "LOW"]);
            }
            _ => panic!("Expected Discrete"),
        }
    }

    #[test]
    fn test_apply_overlay() {
        let mut flags = vec![
            OpenSslFlagDef::boolean("-debug"),
            OpenSslFlagDef {
                name: "-cipher".into(),
                flag_type: FlagType::String,
                arg_hint: Some("val".into()),
                description: String::new(),
            },
        ];

        let mut overlay = HashMap::new();
        overlay.insert(
            "-cipher".to_string(),
            FlagType::Discrete { options: vec!["ALL".into(), "HIGH".into()] },
        );

        apply_overlay(&mut flags, &overlay);

        assert!(matches!(flags[0].flag_type, FlagType::Boolean));
        match &flags[1].flag_type {
            FlagType::Discrete { options } => assert_eq!(options.len(), 2),
            _ => panic!("Expected Discrete"),
        }
    }

    #[test]
    fn test_apply_overlay_unknown_flag_ignored() {
        let mut flags = vec![OpenSslFlagDef::boolean("-debug")];
        let mut overlay = HashMap::new();
        overlay.insert("-nonexistent".to_string(), FlagType::Boolean);
        apply_overlay(&mut flags, &overlay);
        assert!(matches!(flags[0].flag_type, FlagType::Boolean));
    }
}
