//! Hybrid dictionary system: embedded core strings + external dictionary files.
//!
//! Embeds curated naughty strings (from BLNS) and protocol tokens (from AFL++
//! dictionaries) directly in the binary. Also supports loading external `.dict`
//! or `.txt` files at runtime via `--dict`.

use std::fs;
use std::path::Path;

/// Categorized dictionary of fuzzing strings.
#[derive(Debug, Clone, Default)]
pub struct Dictionary {
    /// General naughty strings — injected into string/value/phrase flag pools
    pub strings: Vec<String>,
    /// Header-specific values — injected into --header pool
    pub headers: Vec<String>,
    /// URL-specific values — injected into --url pool
    pub urls: Vec<String>,
    /// Data payload values — injected into --data, --json, etc.
    pub data: Vec<String>,
    /// Protocol commands — injected into --quote, command hints
    pub commands: Vec<String>,
}

impl Dictionary {
    /// Build the embedded core dictionary (naughty strings + protocol tokens).
    pub fn embedded() -> Self {
        let mut d = Dictionary::default();
        d.add_naughty_strings();
        d.add_protocol_tokens();
        d
    }

    /// Load an external dictionary file and merge it into this dictionary.
    /// Supports AFL++ `.dict` format (`"token"` per line) and plain text
    /// (one string per line). Category is inferred from filename or defaults
    /// to `strings`.
    pub fn load_file(&mut self, path: &str) -> Result<usize, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read dictionary file '{}': {}", path, e))?;

        let entries = parse_dict_file(&content);
        let count = entries.len();

        let category = infer_category(path);
        let target = match category {
            DictCategory::Headers => &mut self.headers,
            DictCategory::Urls => &mut self.urls,
            DictCategory::Data => &mut self.data,
            DictCategory::Commands => &mut self.commands,
            DictCategory::Strings => &mut self.strings,
        };
        target.extend(entries);

        Ok(count)
    }

    /// Get all strings for a given category.
    pub fn get(&self, category: &str) -> &[String] {
        match category {
            "strings" => &self.strings,
            "headers" => &self.headers,
            "urls" => &self.urls,
            "data" => &self.data,
            "commands" => &self.commands,
            _ => &[],
        }
    }

    // --- Embedded content ---

    fn add_naughty_strings(&mut self) {
        // Curated from https://github.com/minimaxir/big-list-of-naughty-strings
        self.strings.extend(NAUGHTY_STRINGS.iter().map(|s| s.to_string()));
        self.headers.extend(NAUGHTY_HEADERS.iter().map(|s| s.to_string()));
        self.urls.extend(NAUGHTY_URLS.iter().map(|s| s.to_string()));
        self.data.extend(NAUGHTY_DATA.iter().map(|s| s.to_string()));
    }

    fn add_protocol_tokens(&mut self) {
        // Curated from https://github.com/AFLplusplus/AFLplusplus/tree/stable/dictionaries
        self.headers.extend(HTTP_TOKENS.iter().map(|s| s.to_string()));
        self.data.extend(JSON_TOKENS.iter().map(|s| s.to_string()));
        self.commands.extend(FTP_TOKENS.iter().map(|s| s.to_string()));
        self.commands.extend(SMTP_TOKENS.iter().map(|s| s.to_string()));
    }
}

#[derive(Debug)]
enum DictCategory {
    Strings,
    Headers,
    Urls,
    Data,
    Commands,
}

/// Infer dictionary category from filename.
fn infer_category(path: &str) -> DictCategory {
    let name = Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();

    if name.contains("http") || name.contains("header") {
        DictCategory::Headers
    } else if name.contains("url") || name.contains("uri") {
        DictCategory::Urls
    } else if name.contains("json") || name.contains("xml") || name.contains("data") || name.contains("html") {
        DictCategory::Data
    } else if name.contains("ftp") || name.contains("smtp") || name.contains("imap") || name.contains("command") {
        DictCategory::Commands
    } else {
        DictCategory::Strings
    }
}

/// Parse a dictionary file. Supports:
/// - AFL++ format: `"token"` or `keyword="token"` per line
/// - Plain text: one string per line
/// - Comments: lines starting with `#`
/// - Blank lines are skipped
fn parse_dict_file(content: &str) -> Vec<String> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // AFL++ format: keyword="value" or "value"
        if let Some(entry) = parse_afl_line(line) {
            entries.push(entry);
        } else {
            // Plain text: use the whole line
            entries.push(line.to_string());
        }
    }

    entries
}

/// Parse a single AFL++ dictionary line.
/// Formats: `"token"`, `keyword="token"`, `"escaped\"quote"`
fn parse_afl_line(line: &str) -> Option<String> {
    // Find the quoted portion
    let start = line.find('"')?;
    let rest = &line[start + 1..];

    // Find closing quote (handle escaped quotes)
    let mut result = String::new();
    let mut chars = rest.chars();
    loop {
        match chars.next() {
            None => return None, // unclosed quote
            Some('"') => break,
            Some('\\') => {
                match chars.next() {
                    Some('x') | Some('X') => {
                        // Hex escape: \xNN
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
// Embedded naughty strings (curated from BLNS)
// =============================================================================

/// General naughty strings that break parsers, validators, and display logic.
const NAUGHTY_STRINGS: &[&str] = &[
    // Reserved words
    "undefined", "null", "NULL", "(null)", "nil", "NIL", "true", "false",
    "True", "False", "TRUE", "FALSE", "None", "NaN", "Infinity", "-Infinity",

    // Numeric edge cases
    "0", "-0", "0.0", "-1", "1/0", "-1/0", "0x0", "0xffffffff", "0xffffffffffffffff",
    "9999999999999999999999999999999999999999",
    "1E+99", "1E-99", "-1E+99",
    "999999999999999999999999999999999999999999999999999999999999999e+999999999",

    // Special characters
    ",./;'[]\\-=", "<>?:\"{}|_+", "!@#$%^&*()`~",

    // Whitespace and control
    "\t\n\r", "\x0b\x0c", " \t\r\n",
    "\u{00a0}", // non-breaking space
    "\u{2000}\u{2001}\u{2002}\u{2003}", // various Unicode spaces
    "\u{feff}", // BOM / zero-width no-break space

    // Unicode edge cases
    "\u{0000}", // null
    "\u{200b}", // zero-width space
    "\u{200c}\u{200d}", // zero-width non-joiner / joiner
    "\u{202a}\u{202b}", // LTR/RTL embedding
    "\u{202e}", // RTL override
    "\u{2066}\u{2069}", // isolate controls
    "\u{fffd}", // replacement character
    "\u{fdd0}\u{fdef}", // noncharacters
    "\u{0301}", // combining acute accent (orphan combiner)
    "Ṫ̈̃o͍͊", // zalgo-like combining marks
    "\u{1f4a9}", // pile of poo emoji
    "\u{0000}\u{ffff}", // null + max BMP

    // Injection patterns
    "<script>alert(1)</script>",
    "'--..", // SQL comment
    "' OR '1'='1", // SQLi
    "'; DROP TABLE users;--",
    "{{7*7}}", // template injection
    "${7*7}", // expression language
    "#{7*7}", // Ruby/Java EL
    "%{7*7}", // Struts OGNL
    "{{constructor.constructor('return this')()}}", // prototype pollution
    "${{<%[%'\"}}%\\.", // polyglot

    // Format strings
    "%s%s%s%s%s", "%x%x%x%x", "%n%n%n%n",
    "%d%d%d%d%d%d%d%d%d%d",

    // Path traversal
    "../../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252f", // double-encoded

    // Null bytes
    "\x00", "\x00\x00\x00\x00",
    "test\x00hidden",
    "%00", "%00%00",

    // CRLF injection
    "\r\n", "\r\n\r\n",
    "test\r\nInjected: true",
    "%0d%0a", "%0d%0aInjected:%20true",

    // Command injection (safe — these are string values, not executed)
    "`sleep 5`", "$(sleep 5)", "; sleep 5", "| sleep 5",
    "&& sleep 5", "|| sleep 5",

    // XML/HTML entities
    "&amp;&lt;&gt;&quot;&apos;",
    "&#0;", "&#x0;",
    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",

    // Backslash and quote combos
    "\\", "\\\\", "\\'", "\\\"", "\\0",
    "'", "''", "'''", "\"", "\"\"", "\"\"\"",

    // Emoji edge cases
    "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}\u{200d}\u{1f466}", // family emoji (ZWJ sequence)
    "\u{1f1fa}\u{1f1f8}", // flag emoji (regional indicators)
];

/// Header-specific naughty values.
const NAUGHTY_HEADERS: &[&str] = &[
    // Smuggling
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
    "Transfer-Encoding: \tchunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: chunked\r\nContent-Length: 0",
    // Header injection
    "X-Test: value\r\nX-Injected: true",
    "X-Test: value\r\n\r\nHTTP/1.1 200 OK\r\n",
    // Overlong
    "X-Test: " , // will be extended with long value at runtime
    // Unusual but valid
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary",
    "Content-Type: application/x-www-form-urlencoded; charset=utf-8",
    "Accept-Encoding: gzip, deflate, br, zstd",
    "Range: bytes=0-0",
    "Range: bytes=0-1000000000",
    "If-None-Match: *",
    "Expect: 100-continue",
];

/// URL-specific naughty values.
const NAUGHTY_URLS: &[&str] = &[
    // Protocol confusion
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "gopher://localhost:8080/_GET%20/",
    "dict://localhost:11211/stat",
    // URL parsing edge cases
    "http://localhost:8080/path?q=1&q=2&q=3",
    "http://localhost:8080/path;param=value",
    "http://localhost:8080/path%00hidden",
    "http://localhost:8080/%2e%2e/%2e%2e/etc/passwd",
    "http://localhost:8080/\t\n\r/path",
    "http://localhost:8080/path#frag1#frag2",
    "http://localhost:8080/@",
    "http://localhost:8080/path?key=val%26ue",
    "http://[::ffff:127.0.0.1]:8080/",
    "http://localhost:8080/path?%00=null",
    // Auth in URL
    "http://admin:password@localhost:8080/",
    "http://@localhost:8080/",
    // Backslash (URL parsing inconsistencies)
    "http://localhost:8080\\@evil.com",
    // Long components
    "http://localhost:8080/?x=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
];

/// Data payload naughty values (for --data, --json, etc.)
const NAUGHTY_DATA: &[&str] = &[
    // JSON edge cases
    "{\"__proto__\":{\"admin\":true}}", // prototype pollution
    "{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}",
    "[null,null,null,null,null]",
    "{\"key\":\"\\u0000\"}",
    "{\"key\":\"\\ud800\"}", // lone surrogate
    // Deeply nested
    "[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]",
    "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":{\"i\":{\"j\":1}}}}}}}}}}",
    // Large numbers in JSON
    "{\"num\":99999999999999999999999999999999999999}",
    "{\"num\":1e308}",
    "{\"num\":-1e308}",
    // XML payloads (for content-type confusion)
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
    "<![CDATA[<script>alert(1)</script>]]>",
    // URL-encoded edge cases
    "key=%00&key2=val", // null in urlencoded
    "key=val&key=val2&key=val3", // parameter pollution
    "%00=%00", // null key and value
    "=nokey", // empty key
    "novalue=", // empty value
    "&&&&", // empty parameters
];

// =============================================================================
// Protocol tokens (curated from AFL++ dictionaries)
// =============================================================================

/// HTTP protocol tokens.
const HTTP_TOKENS: &[&str] = &[
    // Methods
    "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",

    // Headers (less common but valid)
    "Accept-Charset: utf-8",
    "Accept-Language: *",
    "Authorization: Basic dGVzdDp0ZXN0",
    "Authorization: Bearer null",
    "Authorization: Digest username=\"test\"",
    "Cache-Control: no-cache, no-store, must-revalidate",
    "Content-Disposition: attachment; filename=\"test.txt\"",
    "Content-Encoding: gzip",
    "Content-Encoding: deflate",
    "Content-Encoding: br",
    "Content-Type: application/octet-stream",
    "Content-Type: multipart/mixed; boundary=boundary",
    "Forwarded: for=127.0.0.1;proto=http;by=127.0.0.1",
    "Origin: http://localhost",
    "Pragma: no-cache",
    "TE: trailers",
    "Trailer: X-Checksum",
    "Upgrade: websocket",
    "Via: 1.1 localhost",
    "X-Forwarded-Host: evil.com",
    "X-Forwarded-Proto: https",
    "X-Original-URL: /admin",
    "X-Rewrite-URL: /admin",
];

/// JSON syntax tokens.
const JSON_TOKENS: &[&str] = &[
    "true", "false", "null",
    "[]", "{}", "\"\"",
    "[{}]", "{\"\":\"\"}", "[null]",
    "[true,false,null,1,\"s\"]",
    "{\"a\":1,\"b\":2,\"c\":3}",
    "0.1", "-0", "1e1", "-1e-1", "1E+1",
    "\"\\u0000\"", "\"\\r\\n\"", "\"\\t\"",
    "\"\\\\\"", "\"\\/\"",
];

/// FTP protocol commands.
const FTP_TOKENS: &[&str] = &[
    "ABOR", "ACCT test", "ADAT", "ALLO 1024", "APPE /tmp/test",
    "AUTH TLS", "AUTH SSL", "CCC", "CDUP", "CONF",
    "CWD /", "CWD /tmp", "DELE /tmp/test",
    "ENC", "EPRT", "EPSV", "FEAT", "HELP",
    "LANG en", "LIST", "LIST -la", "LPRT", "LPSV",
    "MDTM test.txt", "MIC", "MKD /tmp/testdir",
    "MLSD", "MLST", "MODE S", "MODE B", "MODE C",
    "NLST", "NOOP", "OPTS UTF8 ON",
    "PASS test", "PASV", "PBSZ 0", "PORT 127,0,0,1,4,1",
    "PROT P", "PROT C", "PWD", "QUIT", "REIN",
    "REST 0", "RETR test.txt", "RMD /tmp/testdir",
    "RNFR test.txt", "RNTO test2.txt",
    "SITE CHMOD 777 test.txt", "SIZE test.txt",
    "SMNT", "STAT", "STOR /tmp/test", "STOU",
    "STRU F", "STRU R", "STRU P",
    "SYST", "TYPE A", "TYPE I", "TYPE E", "TYPE L 8",
    "USER anonymous", "XCUP", "XMKD", "XPWD", "XRCP", "XRMD",
];

/// SMTP protocol commands.
const SMTP_TOKENS: &[&str] = &[
    "HELO localhost", "EHLO localhost",
    "MAIL FROM:<test@localhost>", "RCPT TO:<test@localhost>",
    "DATA", "RSET", "VRFY test", "EXPN test",
    "NOOP", "QUIT", "HELP",
    "STARTTLS", "AUTH LOGIN", "AUTH PLAIN",
    "TURN", "ETRN localhost",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_dictionary_not_empty() {
        let d = Dictionary::embedded();
        assert!(!d.strings.is_empty());
        assert!(!d.headers.is_empty());
        assert!(!d.urls.is_empty());
        assert!(!d.data.is_empty());
        assert!(!d.commands.is_empty());
    }

    #[test]
    fn test_parse_afl_format() {
        let content = r#"
# comment
"simple"
keyword="value"
"escaped\"quote"
"hex\x41\x42"
"newline\n"
"#;
        let entries = parse_dict_file(content);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0], "simple");
        assert_eq!(entries[1], "value");
        assert_eq!(entries[2], "escaped\"quote");
        assert_eq!(entries[3], "hexAB");
        assert_eq!(entries[4], "newline\n");
    }

    #[test]
    fn test_parse_plain_text() {
        let content = "line one\nline two\n# comment\n\nline three\n";
        let entries = parse_dict_file(content);
        assert_eq!(entries, vec!["line one", "line two", "line three"]);
    }

    #[test]
    fn test_infer_category() {
        assert!(matches!(infer_category("http.dict"), DictCategory::Headers));
        assert!(matches!(infer_category("/path/to/http-headers.txt"), DictCategory::Headers));
        assert!(matches!(infer_category("json.dict"), DictCategory::Data));
        assert!(matches!(infer_category("ftp_commands.dict"), DictCategory::Commands));
        assert!(matches!(infer_category("url-patterns.txt"), DictCategory::Urls));
        assert!(matches!(infer_category("naughty.txt"), DictCategory::Strings));
    }

    #[test]
    fn test_load_file() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("curl-fuzz-dict-test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test-strings.txt");
        {
            let mut f = fs::File::create(&path).unwrap();
            writeln!(f, "naughty1").unwrap();
            writeln!(f, "naughty2").unwrap();
            writeln!(f, "# comment").unwrap();
            writeln!(f, "naughty3").unwrap();
        }

        let mut d = Dictionary::default();
        let count = d.load_file(path.to_str().unwrap()).unwrap();
        assert_eq!(count, 3);
        assert_eq!(d.strings.len(), 3);
        assert_eq!(d.strings[0], "naughty1");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_get_category() {
        let d = Dictionary::embedded();
        assert!(!d.get("strings").is_empty());
        assert!(!d.get("headers").is_empty());
        assert!(d.get("nonexistent").is_empty());
    }

    #[test]
    fn test_naughty_strings_contain_key_patterns() {
        let d = Dictionary::embedded();
        assert!(d.strings.iter().any(|s| s.contains("null")));
        assert!(d.strings.iter().any(|s| s.contains("<script>")));
        assert!(d.strings.iter().any(|s| s.contains("../../../")));
        assert!(d.strings.iter().any(|s| s.contains("%n%n")));
    }

    #[test]
    fn test_protocol_tokens_present() {
        let d = Dictionary::embedded();
        assert!(d.commands.iter().any(|s| s.starts_with("STOR")));
        assert!(d.commands.iter().any(|s| s.starts_with("EHLO")));
        assert!(d.headers.iter().any(|s| s.contains("Authorization")));
    }
}
