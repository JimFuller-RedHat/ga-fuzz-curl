use crate::flag_def::{OpenSslFlagDef, FlagType};
use anyhow::{Context, Result};
use std::process::Command;

const EXCLUDED_FLAGS: &[&str] = &[
    "-help",
    "-ssl_config",
    "-unix",
    "-keylogfile",
    "-writerand",
    "-rand",
    "-msgfile",
    "-sess_out",
    "-sess_in",
    "-early_data",
    // -key, -cert, -CAfile, -CApath, -reconnect UN-EXCLUDED for fuzzing
    "-cert_chain",
    "-CAstore",
    "-CRL",
    "-pass",
    "-provider-path",
    "-provider",
    "-provparam",
    "-propquery",
    "-xkey",
    "-xcert",
    "-xchain",
    "-requestCAfile",
    "-expected-rpks",
    "-psk_session",
    "-chainCAfile",
    "-chainCApath",
    "-chainCAstore",
    "-verifyCAfile",
    "-verifyCApath",
    "-verifyCAstore",
    "-xchain_build",
    "-xcertform",
    "-xkeyform",
];

/// Discover flags for s_client (legacy wrapper using built-in EXCLUDED_FLAGS).
pub fn discover_flags(openssl_path: &str) -> Result<Vec<OpenSslFlagDef>> {
    discover_flags_for(openssl_path, "s_client", &EXCLUDED_FLAGS)
}

/// Discover flags for any openssl subcommand with a custom exclusion list.
pub fn discover_flags_for(
    openssl_path: &str,
    subcommand: &str,
    excluded: &[&str],
) -> Result<Vec<OpenSslFlagDef>> {
    let output = Command::new(openssl_path)
        .args([subcommand, "-help"])
        .output()
        .context(format!("Failed to execute openssl {} -help", subcommand))?;

    // OpenSSL outputs help to stderr
    let text = String::from_utf8(output.stderr)
        .context("Failed to parse openssl help as UTF-8")?;

    let flags = parse_openssl_help(&text)
        .into_iter()
        .filter(|f| !excluded.contains(&f.name.as_str()))
        .collect();

    Ok(flags)
}

pub fn parse_openssl_help(text: &str) -> Vec<OpenSslFlagDef> {
    text.lines()
        .filter_map(parse_help_line)
        .collect()
}

pub fn parse_help_line(line: &str) -> Option<OpenSslFlagDef> {
    let trimmed = line.trim_start();

    // Must start with a dash
    if !trimmed.starts_with('-') {
        return None;
    }

    // Split into tokens by whitespace
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }

    let flag_name = tokens[0].to_string();

    // Determine type from second token (if present)
    let (flag_type, arg_hint, desc_start) = if tokens.len() > 1 {
        match tokens[1] {
            "val" => (FlagType::String, Some("val".to_string()), 2),
            "infile" => (FlagType::String, Some("infile".to_string()), 2),
            "outfile" => (FlagType::String, Some("outfile".to_string()), 2),
            "dir" => (FlagType::String, Some("dir".to_string()), 2),
            "uri" => (FlagType::String, Some("uri".to_string()), 2),
            "+int" => (FlagType::IntegerRange { min: 0, max: 65535 }, Some("+int".to_string()), 2),
            "int" => (FlagType::IntegerRange { min: -1, max: 65535 }, Some("int".to_string()), 2),
            "intmax" => (FlagType::IntegerRange { min: 0, max: 2147483647 }, Some("intmax".to_string()), 2),
            "PEM|DER" => (FlagType::Discrete { options: vec!["PEM".into(), "DER".into()] }, Some("PEM|DER".to_string()), 2),
            "format" => (FlagType::Discrete { options: vec!["PEM".into(), "DER".into(), "P12".into()] }, Some("format".to_string()), 2),
            _ => {
                (FlagType::Boolean, None, 1)
            }
        }
    } else {
        (FlagType::Boolean, None, 1)
    };

    let description = tokens[desc_start..].join(" ");

    Some(OpenSslFlagDef {
        name: flag_name,
        flag_type,
        arg_hint,
        description,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_boolean_flag() {
        let line = " -crlf                      Convert LF from terminal into CRLF";
        let flag = parse_help_line(line).unwrap();
        assert_eq!(flag.name, "-crlf");
        assert!(matches!(flag.flag_type, FlagType::Boolean));
        assert!(flag.description.contains("Convert LF"));
    }

    #[test]
    fn test_parse_val_flag() {
        let line = " -connect val               TCP/IP where to connect; default: 4433)";
        let flag = parse_help_line(line).unwrap();
        assert_eq!(flag.name, "-connect");
        assert!(matches!(flag.flag_type, FlagType::String));
        assert_eq!(flag.arg_hint.as_deref(), Some("val"));
    }

    #[test]
    fn test_parse_int_flag() {
        let line = " -verify +int               Turn on peer certificate verification";
        let flag = parse_help_line(line).unwrap();
        assert_eq!(flag.name, "-verify");
        match flag.flag_type {
            FlagType::IntegerRange { min, max } => {
                assert_eq!(min, 0);
                assert_eq!(max, 65535);
            }
            _ => panic!("Expected IntegerRange"),
        }
    }

    #[test]
    fn test_parse_signed_int_flag() {
        let line = " -verify_depth int          chain depth limit";
        let flag = parse_help_line(line).unwrap();
        assert_eq!(flag.name, "-verify_depth");
        match flag.flag_type {
            FlagType::IntegerRange { min, .. } => assert_eq!(min, -1),
            _ => panic!("Expected IntegerRange"),
        }
    }

    #[test]
    fn test_parse_intmax_flag() {
        let line = " -attime intmax             verification epoch time";
        let flag = parse_help_line(line).unwrap();
        assert_eq!(flag.name, "-attime");
        match flag.flag_type {
            FlagType::IntegerRange { max, .. } => assert_eq!(max, 2147483647),
            _ => panic!("Expected IntegerRange"),
        }
    }

    #[test]
    fn test_parse_pem_der_flag() {
        let line = " -certform PEM|DER          Client certificate file format";
        let flag = parse_help_line(line).unwrap();
        assert_eq!(flag.name, "-certform");
        match flag.flag_type {
            FlagType::Discrete { ref options } => {
                assert!(options.contains(&"PEM".to_string()));
                assert!(options.contains(&"DER".to_string()));
            }
            _ => panic!("Expected Discrete"),
        }
    }

    #[test]
    fn test_parse_format_flag() {
        let line = " -keyform format            Key format (DER/PEM)";
        let flag = parse_help_line(line).unwrap();
        assert_eq!(flag.name, "-keyform");
        match flag.flag_type {
            FlagType::Discrete { ref options } => {
                assert!(options.contains(&"PEM".to_string()));
                assert!(options.contains(&"DER".to_string()));
                assert!(options.contains(&"P12".to_string()));
            }
            _ => panic!("Expected Discrete"),
        }
    }

    #[test]
    fn test_parse_infile_flag() {
        let line = " -cert infile               Client certificate file to use";
        let flag = parse_help_line(line).unwrap();
        assert_eq!(flag.name, "-cert");
        assert!(matches!(flag.flag_type, FlagType::String));
        assert_eq!(flag.arg_hint.as_deref(), Some("infile"));
    }

    #[test]
    fn test_skip_section_header() {
        let line = "General options:";
        assert!(parse_help_line(line).is_none());
    }

    #[test]
    fn test_skip_usage_line() {
        let line = "Usage: s_client [options] [host:port]";
        assert!(parse_help_line(line).is_none());
    }

    #[test]
    fn test_parse_multi_line_help() {
        let text = r#"Usage: s_client [options] [host:port]

General options:
 -help                      Display this summary
 -ct                        Request and parse SCTs

Network options:
 -connect val               TCP/IP where to connect
 -4                         Use IPv4 only
 -maxfraglen +int           Enable Maximum Fragment Length Negotiation

Protocol and version options:
 -tls1_2                    Just use TLSv1.2
 -tls1_3                    Just use TLSv1.3

TLS/SSL options:
 -certform PEM|DER          Client certificate file format
"#;
        let flags = parse_openssl_help(text);
        let names: Vec<&str> = flags.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"-help"));
        assert!(names.contains(&"-ct"));
        assert!(names.contains(&"-connect"));
        assert!(names.contains(&"-4"));
        assert!(names.contains(&"-maxfraglen"));
        assert!(names.contains(&"-tls1_2"));
        assert!(names.contains(&"-tls1_3"));
        assert!(names.contains(&"-certform"));
        // Section headers should not appear
        assert!(!names.iter().any(|n| n.contains("options")));
    }

    #[test]
    fn test_excluded_flags_filtered() {
        let text = r#"
 -help                      Display this summary
 -connect val               TCP/IP where to connect
 -reconnect                 Drop and re-make the connection
 -tls1_2                    Just use TLSv1.2
 -cert infile               Client certificate file to use
 -key infile                Client key file to use
 -CAfile infile             CA certificate file
 -CApath dir                CA certificate path
 -ssl_config val            SSL config section
"#;
        let flags: Vec<OpenSslFlagDef> = parse_openssl_help(text)
            .into_iter()
            .filter(|f| !EXCLUDED_FLAGS.contains(&f.name.as_str()))
            .collect();
        let names: Vec<&str> = flags.iter().map(|f| f.name.as_str()).collect();
        assert!(!names.contains(&"-help"));
        assert!(!names.contains(&"-ssl_config"));
        // These are now UN-excluded for fuzzing
        assert!(names.contains(&"-reconnect"));
        assert!(names.contains(&"-cert"));
        assert!(names.contains(&"-key"));
        assert!(names.contains(&"-CAfile"));
        assert!(names.contains(&"-CApath"));
        assert!(names.contains(&"-connect"));
        assert!(names.contains(&"-tls1_2"));
    }
}
