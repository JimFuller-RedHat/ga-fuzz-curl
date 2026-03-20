//! Hybrid dictionary system for openssl-fuzzer.
//!
//! Embeds curated naughty strings and TLS-specific tokens directly in the
//! binary. Also supports loading external `.dict` or `.txt` files at runtime
//! via `--dict`.

use std::fs;
use std::path::Path;

/// Categorized dictionary of fuzzing strings for openssl s_client.
#[derive(Debug, Clone, Default)]
pub struct Dictionary {
    /// General naughty strings — injected into string-valued flag pools
    pub strings: Vec<String>,
    /// TLS cipher strings
    pub ciphers: Vec<String>,
    /// Protocol/connection values
    pub protocols: Vec<String>,
    /// Certificate/identity values
    pub identities: Vec<String>,
}

impl Dictionary {
    /// Build the embedded core dictionary.
    pub fn embedded() -> Self {
        let mut d = Dictionary::default();
        d.add_naughty_strings();
        d.add_tls_tokens();
        d
    }

    /// Load an external dictionary file and merge it into this dictionary.
    pub fn load_file(&mut self, path: &str) -> Result<usize, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read dictionary file '{}': {}", path, e))?;

        let entries = parse_dict_file(&content);
        let count = entries.len();

        let category = infer_category(path);
        let target = match category {
            DictCategory::Ciphers => &mut self.ciphers,
            DictCategory::Protocols => &mut self.protocols,
            DictCategory::Identities => &mut self.identities,
            DictCategory::Strings => &mut self.strings,
        };
        target.extend(entries);

        Ok(count)
    }

    /// Get all strings for a given category.
    pub fn get(&self, category: &str) -> &[String] {
        match category {
            "strings" => &self.strings,
            "ciphers" => &self.ciphers,
            "protocols" => &self.protocols,
            "identities" => &self.identities,
            _ => &[],
        }
    }

    pub fn total_entries(&self) -> usize {
        self.strings.len() + self.ciphers.len() + self.protocols.len() + self.identities.len()
    }

    fn add_naughty_strings(&mut self) {
        self.strings.extend(NAUGHTY_STRINGS.iter().map(|s| s.to_string()));
    }

    fn add_tls_tokens(&mut self) {
        self.ciphers.extend(TLS_CIPHER_TOKENS.iter().map(|s| s.to_string()));
        self.protocols.extend(TLS_PROTOCOL_TOKENS.iter().map(|s| s.to_string()));
        self.identities.extend(TLS_IDENTITY_TOKENS.iter().map(|s| s.to_string()));
    }
}

#[derive(Debug)]
enum DictCategory {
    Strings,
    Ciphers,
    Protocols,
    Identities,
}

fn infer_category(path: &str) -> DictCategory {
    let name = Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();

    if name.contains("cipher") || name.contains("tls") || name.contains("ssl") {
        DictCategory::Ciphers
    } else if name.contains("protocol") || name.contains("alpn") || name.contains("starttls") {
        DictCategory::Protocols
    } else if name.contains("cert") || name.contains("identity") || name.contains("psk") || name.contains("srp") {
        DictCategory::Identities
    } else {
        DictCategory::Strings
    }
}

/// Parse a dictionary file (AFL++ format or plain text).
fn parse_dict_file(content: &str) -> Vec<String> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(entry) = parse_afl_line(line) {
            entries.push(entry);
        } else {
            entries.push(line.to_string());
        }
    }

    entries
}

fn parse_afl_line(line: &str) -> Option<String> {
    let start = line.find('"')?;
    let rest = &line[start + 1..];

    let mut result = String::new();
    let mut chars = rest.chars();
    loop {
        match chars.next() {
            None => return None,
            Some('"') => break,
            Some('\\') => {
                match chars.next() {
                    Some('x') | Some('X') => {
                        let mut hex = String::new();
                        if let Some(h1) = chars.next() { hex.push(h1); }
                        if let Some(h2) = chars.next() { hex.push(h2); }
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            result.push(byte as char);
                        }
                    }
                    Some('"') => result.push('"'),
                    Some('\\') => result.push('\\'),
                    Some('n') => result.push('\n'),
                    Some('r') => result.push('\r'),
                    Some('t') => result.push('\t'),
                    Some(c) => { result.push('\\'); result.push(c); }
                    None => return None,
                }
            }
            Some(c) => result.push(c),
        }
    }

    Some(result)
}

// =============================================================================
// Embedded naughty strings
// =============================================================================

const NAUGHTY_STRINGS: &[&str] = &[
    // Reserved words
    "undefined", "null", "NULL", "(null)", "nil", "true", "false", "None", "NaN",

    // Numeric edge cases
    "0", "-0", "-1", "0xffffffff", "0xffffffffffffffff",
    "9999999999999999999999999999999999999999",

    // Special characters
    ",./;'[]\\-=", "<>?:\"{}|_+", "!@#$%^&*()`~",

    // Whitespace and control
    "\t\n\r", "\u{00a0}", "\u{feff}",

    // Unicode edge cases
    "\u{0000}", "\u{200b}", "\u{202e}", "\u{fffd}",
    "\u{0301}", // orphan combiner

    // Injection patterns
    "' OR '1'='1", "{{7*7}}", "${7*7}",

    // Format strings
    "%s%s%s%s%s", "%n%n%n%n", "%x%x%x%x",

    // Path traversal
    "../../../../../../../etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",

    // Null bytes
    "\x00", "test\x00hidden", "%00",

    // CRLF injection
    "\r\n", "test\r\nInjected: true",

    // Backslash and quote combos
    "\\", "\\\\", "'", "\"", "''",

    // Long strings (generated at init, but include a moderate one here)
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
];

// =============================================================================
// TLS-specific tokens
// =============================================================================

/// Cipher suite strings — edge cases and unusual combinations.
const TLS_CIPHER_TOKENS: &[&str] = &[
    // Weak/null ciphers that should be rejected
    "eNULL", "aNULL", "NULL-SHA", "NULL-MD5", "NULL-SHA256",
    "EXPORT", "EXP-RC4-MD5", "EXP-DES-CBC-SHA",
    "DES-CBC-SHA", "DES-CBC3-SHA", "RC4-SHA", "RC4-MD5",
    "ADH-AES128-SHA", "ADH-AES256-SHA", // anonymous DH
    "AECDH-AES128-SHA", "AECDH-AES256-SHA", // anonymous ECDH

    // Cipher string operators
    "ALL:!eNULL", "ALL:!aNULL:!EXPORT", "HIGH:!aNULL:!MD5",
    "DEFAULT:!DES:!RC4", "ALL:+RC4", "ALL:@STRENGTH",
    "ALL:!COMPLEMENTOFDEFAULT", "COMPLEMENTOFALL",

    // TLS 1.3 specific
    "TLS_AES_128_CCM_SHA256", "TLS_AES_128_CCM_8_SHA256",

    // Edge cases
    "", // empty cipher string
    "BOGUS_CIPHER_NAME",
    "ALL:ALL:ALL:ALL", // redundant
    "::", // empty entries
    "!ALL", // exclude everything
];

/// Protocol negotiation tokens.
const TLS_PROTOCOL_TOKENS: &[&str] = &[
    // ALPN edge cases
    "h2", "http/1.1", "http/1.0", "spdy/3.1",
    "h2,http/1.1,spdy/3.1", // multiple
    "", // empty
    "x]y[z", // special chars in ALPN
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // long ALPN

    // STARTTLS protocols
    "smtp", "pop3", "imap", "ftp", "xmpp", "lmtp", "nntp", "sieve", "ldap",
    "mysql", "postgres", // not real but interesting to try

    // Server name edge cases
    "localhost", "127.0.0.1", "::1",
    "", // empty SNI
    "a]b[c.com", // special chars in SNI
    ".leading-dot.com",
    "trailing-dot.com.",
    "\x00evil.com", // null byte in SNI
];

/// Certificate/identity tokens.
const TLS_IDENTITY_TOKENS: &[&str] = &[
    // PSK edge cases
    "00", "ff", "deadbeef",
    "0000000000000000000000000000000000000000000000000000000000000000", // 32 bytes
    "", // empty PSK

    // SRP edge cases
    "admin", "root", "test", "",

    // DANE TLSA
    "3 1 1 0000000000000000000000000000000000000000000000000000000000000000",
    "2 0 1 0000000000000000000000000000000000000000000000000000000000000000",
    "3 1 2 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",

    // Signature algorithm edge cases
    "RSA+SHA1", "RSA+MD5", // weak
    "ECDSA+SHA1", // weak ECDSA
    "RSA-PSS+SHA512",
    "ed25519", "ed448",

    // Curve edge cases
    "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1",
    "sect163k1", "sect163r2", // binary curves
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_dictionary_not_empty() {
        let d = Dictionary::embedded();
        assert!(!d.strings.is_empty());
        assert!(!d.ciphers.is_empty());
        assert!(!d.protocols.is_empty());
        assert!(!d.identities.is_empty());
    }

    #[test]
    fn test_total_entries() {
        let d = Dictionary::embedded();
        assert!(d.total_entries() > 50);
    }

    #[test]
    fn test_parse_afl_format() {
        let content = "# comment\n\"simple\"\nkeyword=\"value\"\n";
        let entries = parse_dict_file(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], "simple");
        assert_eq!(entries[1], "value");
    }

    #[test]
    fn test_parse_plain_text() {
        let content = "line one\nline two\n# comment\n\nline three\n";
        let entries = parse_dict_file(content);
        assert_eq!(entries, vec!["line one", "line two", "line three"]);
    }

    #[test]
    fn test_infer_category() {
        assert!(matches!(infer_category("tls-ciphers.dict"), DictCategory::Ciphers));
        assert!(matches!(infer_category("ssl.dict"), DictCategory::Ciphers));
        assert!(matches!(infer_category("alpn.txt"), DictCategory::Protocols));
        assert!(matches!(infer_category("psk.txt"), DictCategory::Identities));
        assert!(matches!(infer_category("naughty.txt"), DictCategory::Strings));
    }

    #[test]
    fn test_get_category() {
        let d = Dictionary::embedded();
        assert!(!d.get("ciphers").is_empty());
        assert!(!d.get("strings").is_empty());
        assert!(d.get("nonexistent").is_empty());
    }

    #[test]
    fn test_cipher_tokens_contain_null() {
        let d = Dictionary::embedded();
        assert!(d.ciphers.iter().any(|s| s.contains("NULL")));
    }

    #[test]
    fn test_load_file() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("openssl-fuzz-dict-test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test-strings.txt");
        {
            let mut f = fs::File::create(&path).unwrap();
            writeln!(f, "naughty1").unwrap();
            writeln!(f, "naughty2").unwrap();
        }

        let mut d = Dictionary::default();
        let count = d.load_file(path.to_str().unwrap()).unwrap();
        assert_eq!(count, 2);
        assert_eq!(d.strings.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }
}
