use crate::dictionaries::Dictionary;
use crate::flag_def::{OpenSslFlagDef, FlagType};
use std::collections::HashMap;

pub fn enrich_flags(flags: &mut [OpenSslFlagDef], dict: Option<&Dictionary>) {
    let by_name = flag_name_seeds();

    for flag in flags.iter_mut() {
        if !matches!(flag.flag_type, FlagType::String) {
            continue;
        }

        if let Some(options) = by_name.get(flag.name.as_str()) {
            flag.flag_type = FlagType::Discrete {
                options: options.clone(),
            };
            continue;
        }

        // Hint-based fallback
        if let Some(ref hint) = flag.arg_hint {
            if let Some(ft) = hint_to_flag_type(hint) {
                flag.flag_type = ft;
            }
        }
    }

    // Merge dictionary entries into existing Discrete pools
    if let Some(dict) = dict {
        for flag in flags.iter_mut() {
            if let FlagType::Discrete { ref mut options } = flag.flag_type {
                let extras = match flag.name.as_str() {
                    "-cipher" | "-ciphersuites" => dict.get("ciphers"),
                    "-alpn" | "-nextprotoneg" | "-starttls"
                    | "-min_protocol" | "-max_protocol" => dict.get("protocols"),
                    "-servername" | "-verify_hostname" | "-xmpphost"
                    | "-ech_outer_sni" => dict.get("protocols"),
                    "-psk" | "-psk_identity" | "-srpuser" | "-srppass"
                    | "-sigalgs" | "-client_sigalgs" | "-groups" | "-curves"
                    | "-dane_tlsa_rrdata" => dict.get("identities"),
                    _ => {
                        match flag.arg_hint.as_deref() {
                            Some("val") => dict.get("strings"),
                            _ => &[],
                        }
                    }
                };
                if !extras.is_empty() {
                    options.extend(extras.iter().cloned());
                }
            }
        }
    }
}

fn hint_to_flag_type(hint: &str) -> Option<FlagType> {
    match hint {
        "val" => None,
        "infile" | "outfile" => Some(discrete(&["/dev/null"])),
        "dir" => Some(discrete(&["/tmp"])),
        "uri" => Some(discrete(&["https://localhost:8443"])),
        _ => None,
    }
}

fn discrete(options: &[&str]) -> FlagType {
    FlagType::Discrete {
        options: options.iter().map(|s| s.to_string()).collect(),
    }
}

fn flag_name_seeds() -> HashMap<&'static str, Vec<String>> {
    let mut m: HashMap<&'static str, Vec<String>> = HashMap::new();
    let s = |v: &[&str]| -> Vec<String> { v.iter().map(|s| s.to_string()).collect() };

    // Connection
    m.insert("-connect", s(&["localhost:8443", "127.0.0.1:8443", "[::1]:8443"]));
    m.insert("-bind", s(&["127.0.0.1", "0.0.0.0", "::1"]));
    m.insert("-proxy", s(&["http://localhost:8080", "socks5://localhost:1080"]));
    m.insert("-proxy_user", s(&["user:pass", "admin:admin"]));
    m.insert("-proxy_pass", s(&["password", "test123", ""]));
    m.insert("-servername", s(&["localhost", "example.com", "test.invalid"]));
    m.insert("-host", s(&["localhost", "127.0.0.1"]));
    m.insert("-name", s(&["localhost", "example.com"]));
    m.insert("-xmpphost", s(&["localhost", "example.com"]));

    // TLS ciphers and algorithms
    m.insert("-cipher", s(&[
        "ALL", "HIGH", "LOW", "MEDIUM", "eNULL", "aNULL",
        "RC4", "DES", "3DES", "AES128", "AES256", "CHACHA20",
    ]));
    m.insert("-ciphersuites", s(&[
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ]));
    m.insert("-sigalgs", s(&[
        "RSA+SHA256", "RSA+SHA384", "ECDSA+SHA256", "RSA-PSS+SHA256",
    ]));
    m.insert("-client_sigalgs", s(&[
        "RSA+SHA256", "ECDSA+SHA256", "RSA-PSS+SHA256",
    ]));
    m.insert("-groups", s(&["P-256", "P-384", "P-521", "X25519", "X448"]));
    m.insert("-curves", s(&["P-256", "P-384", "P-521", "X25519", "X448"]));
    m.insert("-named_curve", s(&["P-256", "P-384", "P-521"]));

    // Protocol negotiation
    m.insert("-alpn", s(&["h2", "http/1.1", "h2,http/1.1"]));
    m.insert("-nextprotoneg", s(&["h2", "http/1.1", "h2,http/1.1"]));
    m.insert("-starttls", s(&["smtp", "pop3", "imap", "ftp", "xmpp", "lmtp"]));

    // Protocol version constraints
    m.insert("-min_protocol", s(&["ssl3", "tls1", "tls1.1", "tls1.2", "tls1.3"]));
    m.insert("-max_protocol", s(&["ssl3", "tls1", "tls1.1", "tls1.2", "tls1.3"]));

    // SRTP
    m.insert("-use_srtp", s(&[
        "SRTP_AES128_CM_SHA1_80", "SRTP_AES128_CM_SHA1_32",
    ]));

    // Validation
    m.insert("-purpose", s(&["sslclient", "sslserver", "any"]));
    m.insert("-verify_name", s(&["default", "pkcs7", "smime_sign", "ssl_client", "ssl_server"]));
    m.insert("-verify_hostname", s(&["localhost", "example.com"]));
    m.insert("-verify_email", s(&["test@example.com"]));
    m.insert("-verify_ip", s(&["127.0.0.1", "::1"]));
    m.insert("-nameopt", s(&["RFC2253", "oneline", "multiline"]));

    // DANE
    m.insert("-dane_tlsa_domain", s(&["localhost", "example.com"]));
    m.insert("-dane_tlsa_rrdata", s(&["3 1 1 aabbccdd"]));

    // PSK
    m.insert("-psk_identity", s(&["test-identity", "client1"]));
    m.insert("-psk", s(&["deadbeef", "0123456789abcdef"]));

    // SRP
    m.insert("-srpuser", s(&["user", "admin", "test"]));
    m.insert("-srppass", s(&["password", "test123"]));

    // ECH
    m.insert("-ech_outer_alpn", s(&["h2", "http/1.1"]));
    m.insert("-ech_outer_sni", s(&["localhost", "example.com"]));

    // Policy
    m.insert("-policy", s(&["1.2.3.4", "2.5.29.32.0"]));

    // CMS-specific seeds
    m.insert("-inform", s(&["SMIME", "PEM", "DER"]));
    m.insert("-outform", s(&["SMIME", "PEM", "DER"]));
    m.insert("-rctform", s(&["PEM", "DER"]));
    m.insert("-md", s(&["sha1", "sha256", "sha384", "sha512", "md5"]));
    m.insert("-secretkey", s(&["deadbeef0123456789abcdef01234567"]));
    m.insert("-secretkeyid", s(&["fuzz-key-id"]));
    m.insert("-pwri_password", s(&["password", "test123", "", "a]b[c"]));
    m.insert("-subject", s(&["/CN=test", "/CN=fuzz/O=test", ""]));
    m.insert("-from", s(&["test@example.com", "fuzz@test.invalid"]));
    m.insert("-to", s(&["recipient@example.com"]));
    m.insert("-verify_hostname", s(&["localhost", "example.com", "test.invalid"]));
    m.insert("-verify_email", s(&["test@example.com"]));
    m.insert("-verify_ip", s(&["127.0.0.1", "::1"]));
    m.insert("-kekcipher", s(&["aes-128-cbc", "aes-256-cbc"]));
    m.insert("-wrap", s(&["aes-128-wrap", "aes-256-wrap", "des3-wrap"]));
    m.insert("-keyform", s(&["PEM", "DER"]));
    m.insert("-certform", s(&["PEM", "DER"]));
    m.insert("-CRLform", s(&["PEM", "DER"]));

    // Record padding
    m.insert("-record_padding", s(&["0", "256", "512", "1024", "16384"]));

    // Server info
    m.insert("-serverinfo", s(&["1", "2", "1,2"]));

    // ECH config
    m.insert("-ech_config_list", s(&["AAAA"]));
    m.insert("-ech_grease_suite", s(&["0x0020,0x0001,0x0001"]));

    // Client certificate (un-excluded for fuzzing)
    m.insert("-cert", s(&[
        "/tmp/curl-fuzz-certs/server.crt", "/dev/null", "/nonexistent",
    ]));
    m.insert("-key", s(&[
        "/tmp/curl-fuzz-certs/server.key", "/dev/null", "/nonexistent",
    ]));
    m.insert("-CAfile", s(&[
        "/tmp/curl-fuzz-certs/server.crt", "/dev/null", "/nonexistent",
    ]));
    m.insert("-CApath", s(&[
        "/tmp/curl-fuzz-certs", "/tmp", "/nonexistent",
    ]));

    m
}

/// Add fixture file paths as seeds for `-in` and similar input-file flags.
pub fn add_input_file_seeds(flags: &mut [OpenSslFlagDef], fixture_files: &[String]) {
    let input_flags = ["-in", "-trusted", "-untrusted", "-CAfile", "-CRLfile",
                       "-content", "-verify_receipt"];
    let input_hints = ["infile"];

    for flag in flags.iter_mut() {
        let is_input = input_flags.contains(&flag.name.as_str())
            || flag.arg_hint.as_deref().map_or(false, |h| input_hints.contains(&h));

        if !is_input {
            continue;
        }

        let mut seeds: Vec<String> = fixture_files.to_vec();
        // Also include /dev/null and a nonexistent path
        seeds.push("/dev/null".to_string());
        seeds.push("/nonexistent".to_string());

        match &mut flag.flag_type {
            FlagType::Discrete { options } => {
                for s in &seeds {
                    if !options.contains(s) {
                        options.push(s.clone());
                    }
                }
            }
            _ => {
                flag.flag_type = FlagType::Discrete { options: seeds };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrich_cipher_flag() {
        let mut flags = vec![OpenSslFlagDef {
            name: "-cipher".into(),
            flag_type: FlagType::String,
            arg_hint: Some("val".into()),
            description: String::new(),
        }];

        enrich_flags(&mut flags, None);

        match &flags[0].flag_type {
            FlagType::Discrete { options } => {
                assert!(options.contains(&"ALL".to_string()));
                assert!(options.contains(&"HIGH".to_string()));
            }
            other => panic!("Expected Discrete, got {:?}", other),
        }
    }

    #[test]
    fn test_enrich_skips_already_typed() {
        let mut flags = vec![OpenSslFlagDef {
            name: "-cipher".into(),
            flag_type: FlagType::IntegerRange { min: 0, max: 10 },
            arg_hint: None,
            description: String::new(),
        }];

        enrich_flags(&mut flags, None);

        assert!(matches!(flags[0].flag_type, FlagType::IntegerRange { .. }));
    }

    #[test]
    fn test_enrich_infile_hint_fallback() {
        let mut flags = vec![OpenSslFlagDef {
            name: "-some_unknown_file".into(),
            flag_type: FlagType::String,
            arg_hint: Some("infile".into()),
            description: String::new(),
        }];

        enrich_flags(&mut flags, None);

        match &flags[0].flag_type {
            FlagType::Discrete { options } => {
                assert!(options.contains(&"/dev/null".to_string()));
            }
            other => panic!("Expected Discrete, got {:?}", other),
        }
    }

    #[test]
    fn test_add_input_file_seeds() {
        let mut flags = vec![OpenSslFlagDef {
            name: "-in".into(),
            flag_type: FlagType::String,
            arg_hint: Some("infile".into()),
            description: "input file".into(),
        }];
        let files = vec!["/tmp/a.pem".to_string(), "/tmp/b.der".to_string()];
        add_input_file_seeds(&mut flags, &files);
        match &flags[0].flag_type {
            FlagType::Discrete { options } => {
                assert!(options.contains(&"/tmp/a.pem".to_string()));
                assert!(options.contains(&"/tmp/b.der".to_string()));
            }
            _ => panic!("Expected Discrete after add_input_file_seeds"),
        }
    }

    #[test]
    fn test_enrich_unknown_stays_string() {
        let mut flags = vec![OpenSslFlagDef {
            name: "-totally_unknown".into(),
            flag_type: FlagType::String,
            arg_hint: Some("val".into()),
            description: String::new(),
        }];

        enrich_flags(&mut flags, None);

        assert!(matches!(flags[0].flag_type, FlagType::String));
    }
}
