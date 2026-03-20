//! Seed values for curl flags based on argument hint types and flag names.
//!
//! When curl's `--help all` says `--output <file>`, the hint is "file".
//! This module maps those hints (and specific flag names) to pools of
//! realistic values the fuzzer can pick from, converting FlagType::String
//! into FlagType::Discrete with meaningful options.

use crate::dictionaries::Dictionary;
use crate::flag_def::{CurlFlagDef, FlagType};
use std::collections::HashMap;

/// Auto-enrich flags that are still FlagType::String by looking at
/// their arg_hint and flag name to assign a Discrete value pool.
/// If a Dictionary is provided, its entries are appended to matching pools.
pub fn enrich_flags(flags: &mut [CurlFlagDef], dict: Option<&Dictionary>) {
    let by_name = flag_name_seeds();

    for flag in flags.iter_mut() {
        // Skip flags already enriched by the overlay
        if !matches!(flag.flag_type, FlagType::String) {
            continue;
        }

        // First try exact flag name match
        if let Some(options) = by_name.get(flag.name.as_str()) {
            flag.flag_type = FlagType::Discrete {
                options: options.clone(),
            };
            continue;
        }

        // Then try hint-based classification
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
                    "--header" | "--proxy-header" => dict.get("headers"),
                    "--url" | "--referer" | "--doh-url" => dict.get("urls"),
                    "--data" | "--data-raw" | "--data-binary" | "--json"
                    | "--data-urlencode" => dict.get("data"),
                    "--quote" | "--ftp-account" => dict.get("commands"),
                    _ => {
                        // For general string-valued flags, add naughty strings
                        match flag.arg_hint.as_deref() {
                            Some("string") | Some("value") | Some("phrase")
                            | Some("data") => dict.get("strings"),
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

/// Map arg hint strings to appropriate FlagTypes.
fn hint_to_flag_type(hint: &str) -> Option<FlagType> {
    match hint {
        // Time values
        "seconds" => Some(FlagType::IntegerRange { min: 1, max: 300 }),
        "ms" => Some(FlagType::IntegerRange { min: 100, max: 30000 }),

        // Numeric
        "num" | "integer" => Some(FlagType::IntegerRange { min: 0, max: 1000 }),
        "bytes" => Some(FlagType::IntegerRange { min: 0, max: 1048576 }),
        "speed" => Some(FlagType::IntegerRange { min: 0, max: 1000000 }),
        "max request rate" => Some(FlagType::IntegerRange { min: 1, max: 100 }),
        "mode" => Some(FlagType::IntegerRange { min: 0, max: 777 }),

        // File paths
        "file" | "filename" => Some(discrete(&[
            "/dev/null", "/tmp/curl-fuzz-out", "/tmp/curl-fuzz-upload", "-",
        ])),

        // Directories
        "dir" | "path" => Some(discrete(&["/tmp", "/tmp/curl-fuzz", "/dev/null"])),

        // URLs
        "url" => Some(discrete(&[
            "http://localhost:8080", "http://localhost:8080/test",
            "https://localhost:8443", "http://localhost:8080/redirect",
        ])),

        // Data payloads
        "data" => {
            let mut opts = vec![
                "".into(), "key=value".into(), "foo=bar&baz=qux".into(),
                "{\"key\":\"value\"}".into(), "a]b[c".into(),
                "%00%01%02".into(), "%n%n%n%n".into(),
                "\x00\x01\x02\x03".into(),
                "key=value&key=value&key=value".into(),
            ];
            opts.push("A".repeat(256));
            opts.push("A".repeat(8192));
            opts.push("%s".repeat(50));
            Some(FlagType::Discrete { options: opts })
        }

        // Host/address patterns
        "host[:port]" | "[protocol://]host[:port]" => Some(discrete(&[
            "localhost:8080", "127.0.0.1:8080", "[::1]:8080", "localhost:8443",
        ])),

        "address" | "addresses" => Some(discrete(&[
            "127.0.0.1", "0.0.0.0", "::1", "localhost",
        ])),

        "ip" => Some(discrete(&["127.0.0.1", "0.0.0.0", "::1", "192.168.1.1"])),

        // Network interface
        "interface" | "name" => Some(discrete(&["lo", "eth0", "lo0"])),

        // Crypto/TLS
        "list" => Some(discrete(&["DEFAULT", "ALL", "HIGH", "MEDIUM", "LOW", "NULL"])),
        "key" | "cert[:passwd]" => Some(discrete(&["/dev/null"])),
        "type" => Some(discrete(&["PEM", "DER", "ENG", "P12"])),
        "hashes" | "md5" | "sha256" => Some(discrete(&[
            "0000000000000000000000000000000000000000000000000000000000000000",
        ])),

        // Auth
        "identity" | "token" => Some(discrete(&["test-token", "Bearer test123", ""])),

        // Protocol
        "protocol" | "protocols" => Some(discrete(&["http", "https", "ftp", "smtp", "imap"])),
        "method" => Some(discrete(&["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])),
        "level" => Some(discrete(&["none", "policy", "always"])),

        // Headers
        "header/@file" => Some(discrete(&[
            "X-Fuzz: test", "Content-Type: application/json",
            "Content-Type: text/html", "Accept: */*",
            "X-Custom: \r\nInjected: true", "Connection: close",
            "Transfer-Encoding: chunked",
        ])),

        // Generic strings
        "string" | "value" | "phrase" => {
            let mut opts = vec![
                "test".into(), "".into(), "fuzz-value".into(),
                "a]b[c".into(), "../../../etc/passwd".into(),
                "%n%n%n%n".into(), "%s%s%s%s".into(),
                "\x00".into(), "\r\n\r\n".into(),
                "{{7*7}}".into(), "${PATH}".into(),
                "\u{FEFF}test".into(), // BOM
                "\u{0000}null".into(),
            ];
            opts.push("A".repeat(4096));
            Some(FlagType::Discrete { options: opts })
        }

        // Proxy
        "no-proxy-list" => Some(discrete(&["localhost", "*", "127.0.0.1", ""])),

        // User credentials
        "user:password" => Some(discrete(&[
            "user:pass", "admin:admin", "test:", ":password",
        ])),
        "certificate[:password]" => Some(discrete(&["/dev/null"])),

        // Commands / config
        "command" => Some(discrete(&["STAT", "NOOP", "PWD", "LIST"])),
        "format" => Some(discrete(&[
            "%{http_code}", "%{time_total}", "%{size_download}",
            "%{url_effective}", "%{exitcode}",
        ])),

        // Connect-to / resolve
        "host1:port1:host2:port2" => Some(discrete(&[
            "localhost:8080:localhost:8080",
            "example.com:443:localhost:8443",
        ])),
        "[+]host:port:addr[,addr]..." => Some(discrete(&[
            "localhost:8080:127.0.0.1",
            "*:8080:127.0.0.1",
        ])),

        // Form fields
        "name=content" | "name=string" | "[%]name=text/@file" => Some(discrete(&[
            "name=value", "file=@/dev/null", "key=test",
            "data=@/dev/null;type=text/plain",
        ])),

        // Misc
        "offset" => Some(FlagType::IntegerRange { min: 0, max: 10000 }),
        "options" | "opt=val" | "flags" => Some(discrete(&["test", ""])),
        "subject" => Some(discrete(&["Test Subject", ""])),
        "time" => Some(discrete(&["Mon, 01 Jan 2024 00:00:00 GMT", "-1", "0"])),
        "version" | "VERSION" => Some(discrete(&["1.0", "1.1", "2", "3"])),
        "active/passive" => Some(discrete(&["active", "passive"])),
        "data|filename" => Some(discrete(&[
            "key=value", "@/dev/null", "{\"key\":\"value\"}",
        ])),
        "priority" => Some(FlagType::IntegerRange { min: 0, max: 256 }),
        "config" => Some(discrete(&["/dev/null"])),
        "range" => Some(discrete(&["0-99", "0-0", "100-199", "-500", "0-"])),

        _ => None,
    }
}

fn discrete(options: &[&str]) -> FlagType {
    FlagType::Discrete {
        options: options.iter().map(|s| s.to_string()).collect(),
    }
}

/// Flag-name-specific seed values that override hint-based classification.
/// These handle flags where the hint is too generic or where we know
/// exactly what curl expects.
fn flag_name_seeds() -> HashMap<&'static str, Vec<String>> {
    let mut m: HashMap<&'static str, Vec<String>> = HashMap::new();

    let s = |v: &[&str]| -> Vec<String> { v.iter().map(|s| s.to_string()).collect() };

    // Request method
    m.insert("--request", s(&[
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE",
    ]));

    // User credentials
    m.insert("--user", s(&[
        "user:pass", "admin:admin", "foo:bar", "test:", ":password",
    ]));
    m.insert("--proxy-user", s(&["user:pass", "admin:admin"]));

    // User-Agent
    m.insert("--user-agent", {
        let mut v = s(&[
            "curl/8.0", "Mozilla/5.0", "curl-fuzzer/1.0", "",
            "() { :;}; /bin/bash -c 'echo vulnerable'", // shellshock
            "%n%n%n%n", // format string
            "\r\nX-Injected: true", // header injection
        ]);
        v.push("A".repeat(256));
        v.push("A".repeat(8192));
        v
    });

    // Referer
    m.insert("--referer", s(&[
        "http://localhost:8080", "http://evil.com", "", "javascript:alert(1)",
    ]));

    // Cookie
    m.insert("--cookie", {
        let mut v = s(&[
            "session=abc123", "a=1; b=2; c=3", "", "name=value\r\nInjected: true",
            "a=b; c=d; e=f; g=h; i=j; k=l; m=n; o=p", // many cookies
            "name=\x00value", // null in value
            "session=abc123; path=/; domain=evil.com; HttpOnly; Secure",
        ]);
        v.push(format!("session={}", "A".repeat(4096))); // oversized cookie
        v
    });

    // Headers
    m.insert("--header", {
        let mut v = s(&[
            "X-Fuzz: test", "Content-Type: application/json", "Content-Type: text/xml",
            "Accept: */*", "X-Custom: \r\nInjected: true", "Connection: close",
            "Transfer-Encoding: chunked", "Content-Length: 0", "Host: evil.com",
            "Expect: 100-continue",
            "Content-Length: -1", "Content-Length: 99999999",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity", // TE smuggling
            "Host: localhost\r\nHost: evil.com", // duplicate host
            "X-Empty:", // empty header value
            "X-Null: \x00value", // null byte
            ": no-name", // empty header name
            "Connection: keep-alive",
            "Proxy-Connection: keep-alive",
            "X-Forwarded-For: 127.0.0.1",
        ]);
        v.push(format!("X-Long: {}", "B".repeat(8192))); // oversized header
        v
    });

    // Proxy
    m.insert("--proxy", s(&["http://localhost:8080", "socks5://localhost:1080", "http://127.0.0.1:3128"]));
    m.insert("--socks5", s(&["localhost:1080", "127.0.0.1:1080"]));
    m.insert("--noproxy", s(&["localhost", "*", "127.0.0.1"]));

    // URL
    m.insert("--url", {
        let mut v = s(&[
            "http://localhost:8080", "http://localhost:8080/test", "https://localhost:8443",
            "ftp://localhost:2121", "http://localhost:8080/%00",
            "http://localhost:8080/../../etc/passwd", "http://localhost:8080/a?b=c&d=e",
            "http://localhost:8080/%252e%252e%252f", // double-encoded traversal
            "http://localhost:8080/\r\n\r\n", // CRLF in path
            "http://user:pass@localhost:8080/", // credentials in URL
            "http://localhost:8080/#fragment",
            "http://localhost:8080/?%00=null", // null in query
            "http://[::1]:8080/", // IPv6
            "http://0x7f000001:8080/", // hex IP
        ]);
        v.push(format!("http://localhost:8080/{}", "A".repeat(4096))); // long path
        v
    });
    m.insert("--doh-url", s(&["https://localhost:8443/dns-query"]));

    // Data/POST
    m.insert("--data", {
        let mut v = s(&[
            "key=value", "{\"key\":\"value\"}", "foo=bar&baz=qux", "", "%00%01%02",
            "%n%n%n%n", "\x00\x01\x02\x03",
            "key=value&key=value&key=value", // duplicate keys
        ]);
        v.push("A".repeat(8192)); // large payload
        v.push(format!("key={}", "B".repeat(4096))); // oversized value
        v
    });
    m.insert("--data-raw", {
        let mut v = s(&["key=value", "@/dev/null", "{\"a\":1}", "\x00\x00\x00\x00"]);
        v.push("C".repeat(8192));
        v
    });
    m.insert("--data-urlencode", s(&["key=hello world", "data=special&chars=here", "name=foo bar", "=nokey", "novalue="]));
    m.insert("--data-binary", {
        let mut v = s(&["@/dev/null", "binary-content", "\x00\x01\x02\x03"]);
        // Add high-byte binary content
        v.push(String::from_utf8_lossy(&[0xffu8, 0xfeu8, 0x00, 0x01]).to_string());
        v.push(String::from_utf8_lossy(&vec![0xffu8; 1024]).to_string());
        v
    });
    m.insert("--json", {
        let mut v = s(&[
            "{}", "{\"key\":\"value\"}", "[1,2,3]",
            "{\"a\":{\"b\":{\"c\":\"deep\"}}}", "null", "\"string\"",
            "{{bad json", "[[[[[[[[[", // deeply nested / malformed
            "{\"key\": \"\\u0000\"}", // null in json
        ]);
        v.push(format!("{{\"key\":\"{}\"}}", "D".repeat(4096))); // large json value
        v
    });

    // Form data
    m.insert("--form", s(&["file=@/dev/null", "name=value", "data=@/dev/null;type=text/plain"]));
    m.insert("--form-string", s(&["name=value", "key=test data"]));

    // Output
    m.insert("--output", s(&["/dev/null", "/tmp/curl-fuzz-out", "-"]));
    m.insert("--dump-header", s(&["/dev/null", "/tmp/curl-fuzz-headers", "-"]));
    m.insert("--trace", s(&["/dev/null", "/tmp/curl-fuzz-trace"]));
    m.insert("--trace-ascii", s(&["/dev/null"]));
    m.insert("--stderr", s(&["/dev/null", "-"]));

    // Upload
    m.insert("--upload-file", s(&["/dev/null", "/tmp/curl-fuzz-upload"]));

    // Write-out format
    m.insert("--write-out", s(&["%{http_code}", "%{time_total}", "%{size_download}"]));

    // Range
    m.insert("--range", s(&["0-99", "0-0", "100-199", "-500", "0-"]));

    // Resolve / connect
    m.insert("--resolve", s(&["localhost:8080:127.0.0.1", "*:8080:127.0.0.1"]));
    m.insert("--connect-to", s(&["localhost:8080:localhost:8080"]));

    // FTP
    m.insert("--quote", s(&["STAT", "PWD", "NOOP"]));
    m.insert("--ftp-method", s(&["multicwd", "nocwd", "singlecwd"]));
    m.insert("--ftp-ssl-ccc-mode", s(&["active", "passive"]));

    // Auth tokens
    m.insert("--oauth2-bearer", s(&["test-token-12345", ""]));
    m.insert("--aws-sigv4", s(&["aws:amz:us-east-1:s3"]));
    m.insert("--delegation", s(&["none", "policy", "always"]));

    // Cache files
    m.insert("--alt-svc", s(&["/dev/null", "/tmp/curl-fuzz-altsvc"]));
    m.insert("--hsts", s(&["/dev/null", "/tmp/curl-fuzz-hsts"]));

    // Ciphers
    m.insert("--ciphers", s(&["DEFAULT", "ALL", "HIGH", "eNULL", "AES256-SHA"]));
    m.insert("--tls13-ciphers", s(&["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"]));
    m.insert("--curves", s(&["X25519", "P-256", "P-384"]));

    // IP TOS
    m.insert("--ip-tos", s(&[
        "cs0", "cs1", "cs2", "cs3", "cs4", "cs5", "cs6", "cs7",
        "af11", "af21", "af31", "af41", "ef", "lowdelay", "throughput", "reliability",
    ]));

    // DNS
    m.insert("--dns-servers", s(&["127.0.0.1", "8.8.8.8"]));

    // Protocols
    m.insert("--proto", s(&["=http,https", "=http", "-all,+http", "=ftp"]));
    m.insert("--proto-redir", s(&["=http,https", "=https"]));

    // Service name
    m.insert("--service-name", s(&["HTTP", "http"]));

    // Mail
    m.insert("--mail-from", s(&["sender@localhost", "test@example.com"]));
    m.insert("--mail-rcpt", s(&["recipient@localhost", "test@example.com"]));

    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrich_converts_string_to_discrete() {
        let mut flags = vec![
            CurlFlagDef {
                name: "--request".to_string(),
                flag_type: FlagType::String,
                arg_hint: Some("method".to_string()),
                description: String::new(),
                requires: Vec::new(),
            },
        ];

        enrich_flags(&mut flags, None);

        match &flags[0].flag_type {
            FlagType::Discrete { options } => {
                assert!(options.contains(&"GET".to_string()));
                assert!(options.contains(&"POST".to_string()));
            }
            other => panic!("Expected Discrete, got {:?}", other),
        }
    }

    #[test]
    fn test_enrich_uses_hint_when_no_name_match() {
        let mut flags = vec![
            CurlFlagDef {
                name: "--some-timeout".to_string(),
                flag_type: FlagType::String,
                arg_hint: Some("seconds".to_string()),
                description: String::new(),
                requires: Vec::new(),
            },
        ];

        enrich_flags(&mut flags, None);

        match &flags[0].flag_type {
            FlagType::IntegerRange { min, max } => {
                assert_eq!(*min, 1);
                assert_eq!(*max, 300);
            }
            other => panic!("Expected IntegerRange, got {:?}", other),
        }
    }

    #[test]
    fn test_enrich_skips_already_typed() {
        let mut flags = vec![
            CurlFlagDef {
                name: "--connect-timeout".to_string(),
                flag_type: FlagType::IntegerRange { min: 1, max: 30 },
                arg_hint: Some("seconds".to_string()),
                description: String::new(),
                requires: Vec::new(),
            },
        ];

        enrich_flags(&mut flags, None);

        // Should not change
        match &flags[0].flag_type {
            FlagType::IntegerRange { min, max } => {
                assert_eq!(*min, 1);
                assert_eq!(*max, 30);
            }
            other => panic!("Expected original IntegerRange, got {:?}", other),
        }
    }

    #[test]
    fn test_enrich_file_hint() {
        let mut flags = vec![
            CurlFlagDef {
                name: "--cacert".to_string(),
                flag_type: FlagType::String,
                arg_hint: Some("file".to_string()),
                description: String::new(),
                requires: Vec::new(),
            },
        ];

        enrich_flags(&mut flags, None);

        match &flags[0].flag_type {
            FlagType::Discrete { options } => {
                assert!(options.contains(&"/dev/null".to_string()));
            }
            other => panic!("Expected Discrete, got {:?}", other),
        }
    }

    #[test]
    fn test_enrich_header_flag() {
        let mut flags = vec![
            CurlFlagDef {
                name: "--header".to_string(),
                flag_type: FlagType::String,
                arg_hint: Some("header/@file".to_string()),
                description: String::new(),
                requires: Vec::new(),
            },
        ];

        enrich_flags(&mut flags, None);

        match &flags[0].flag_type {
            FlagType::Discrete { options } => {
                assert!(options.iter().any(|o| o.contains("Content-Type")));
            }
            other => panic!("Expected Discrete, got {:?}", other),
        }
    }
}
