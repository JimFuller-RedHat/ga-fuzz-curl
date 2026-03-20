use crate::flag_def::{CurlFlagDef, FlagType};
use anyhow::{Context, Result};
use std::process::Command;

/// Flags that should never be fuzzed because they're dangerous, interactive,
/// or produce no useful fuzzing signal.
const EXCLUDED_FLAGS: &[&str] = &[
    "--help",       // prints help and exits
    "--version",    // prints version and exits
    "--manual",     // opens man page (blocks)
    "--config",     // reads arbitrary config file
    "--libcurl",    // generates C source code
    "--metalink",   // deprecated/removed in modern curl
    "--test-event", // internal testing only
    "--write-out",  // we inject our own -w, don't conflict
    "-K",           // short form of --config
    "-V",           // short form of --version
    "-h",           // short form of --help
    "-M",           // short form of --manual
    "--parallel-max", // can cause resource exhaustion
    "--rate",       // can cause very slow runs
];

pub fn discover_flags(curl_path: &str) -> Result<Vec<CurlFlagDef>> {
    let output = Command::new(curl_path)
        .arg("--help")
        .arg("all")
        .output()
        .context("Failed to execute curl --help all")?;

    let text = String::from_utf8(output.stdout)
        .context("Failed to parse curl help output as UTF-8")?;

    let flags = parse_curl_help(&text)
        .into_iter()
        .filter(|f| !EXCLUDED_FLAGS.contains(&f.name.as_str()))
        .collect();

    Ok(flags)
}

pub fn parse_curl_help(text: &str) -> Vec<CurlFlagDef> {
    text.lines()
        .filter_map(parse_help_line)
        .collect()
}

pub fn parse_help_line(line: &str) -> Option<CurlFlagDef> {
    let trimmed = line.trim_start();

    // Must start with a dash
    if !trimmed.starts_with('-') {
        return None;
    }

    // Find the flag name(s) and description
    let parts: Vec<&str> = trimmed.splitn(2, "  ").collect();
    if parts.is_empty() {
        return None;
    }

    let flag_part = parts[0].trim();
    let description = if parts.len() > 1 {
        parts[1].trim().to_string()
    } else {
        String::new()
    };

    // Parse the flag part to extract the long form and check for arguments
    let mut flag_name = String::new();
    let mut has_arg = false;
    let mut arg_hint = None;

    // Split by comma to handle "-o, --output <file>" format
    let flag_tokens: Vec<&str> = flag_part.split(',').collect();

    for token in flag_tokens {
        let token = token.trim();

        // Extract <hint> if present
        if let (Some(start), Some(end)) = (token.find('<'), token.find('>')) {
            has_arg = true;
            arg_hint = Some(token[start + 1..end].to_lowercase());
        }

        // Extract the flag name (before any <arg>)
        let flag_only = token.split_whitespace().next().unwrap_or("");

        // Prefer the long form (starts with --)
        if flag_only.starts_with("--") {
            flag_name = flag_only.to_string();
        } else if flag_name.is_empty() && flag_only.starts_with('-') {
            flag_name = flag_only.to_string();
        }
    }

    if flag_name.is_empty() {
        return None;
    }

    let flag_type = if has_arg {
        FlagType::String
    } else {
        FlagType::Boolean
    };

    Some(CurlFlagDef {
        name: flag_name,
        flag_type,
        arg_hint,
        description,
        requires: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_boolean_flag() {
        let line = "     --compressed       Request compressed response";
        let flag = parse_help_line(line).expect("Should parse boolean flag");

        assert_eq!(flag.name, "--compressed");
        assert_eq!(flag.description, "Request compressed response");
        match flag.flag_type {
            FlagType::Boolean => {}
            _ => panic!("Expected Boolean flag type"),
        }
    }

    #[test]
    fn test_parse_flag_with_arg() {
        let line = "     --connect-timeout <seconds>  Maximum time";
        let flag = parse_help_line(line).expect("Should parse flag with arg");

        assert_eq!(flag.name, "--connect-timeout");
        assert_eq!(flag.description, "Maximum time");
        match flag.flag_type {
            FlagType::String => {}
            _ => panic!("Expected String flag type"),
        }
    }

    #[test]
    fn test_parse_short_and_long() {
        let line = " -o, --output <file>   Write to file";
        let flag = parse_help_line(line).expect("Should parse short and long flag");

        assert_eq!(flag.name, "--output");
        assert_eq!(flag.description, "Write to file");
        match flag.flag_type {
            FlagType::String => {}
            _ => panic!("Expected String flag type"),
        }
    }

    #[test]
    fn test_parse_non_flag_line() {
        let line = "Usage: curl [options...] <url>";
        let result = parse_help_line(line);

        assert!(result.is_none(), "Should not parse non-flag line");
    }

    #[test]
    fn test_parse_multi_line_help() {
        let text = r#"Usage: curl [options...] <url>
     --compressed       Request compressed response
 -v, --verbose          Make the operation more talkative
     --connect-timeout <seconds>  Maximum time allowed for connection
     --max-time <seconds>         Maximum time allowed for transfer
"#;
        let flags = parse_curl_help(text);

        assert_eq!(flags.len(), 4);
        assert_eq!(flags[0].name, "--compressed");
        assert_eq!(flags[1].name, "--verbose");
        assert_eq!(flags[2].name, "--connect-timeout");
        assert_eq!(flags[3].name, "--max-time");
    }
}
