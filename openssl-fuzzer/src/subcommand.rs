/// Defines fuzzable OpenSSL subcommands and their per-subcommand configuration.

#[derive(Debug, Clone, PartialEq)]
pub enum SubCommandKind {
    SClient,
    X509,
    Asn1parse,
    Verify,
    Req,
    Enc,
    Cms,
}

#[derive(Debug, Clone)]
pub struct SubCommandDef {
    pub kind: SubCommandKind,
    /// The openssl subcommand name (e.g. "s_client", "x509")
    pub name: &'static str,
    /// Fixed args prepended before the fuzzed flags
    pub fixed_args: Vec<String>,
    /// Whether to pipe stdin (e.g. "Q\n" for s_client)
    pub stdin_input: Option<&'static str>,
    /// Flags to exclude from fuzzing for this subcommand
    pub excluded_flags: Vec<&'static str>,
    /// Whether this subcommand needs input files (certs, DER, etc.)
    pub needs_input_files: bool,
    /// Description for CLI help
    pub description: &'static str,
}

impl SubCommandDef {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "s_client" => Some(Self::s_client("localhost:8443")),
            "x509" => Some(Self::x509()),
            "asn1parse" => Some(Self::asn1parse()),
            "verify" => Some(Self::verify()),
            "req" => Some(Self::req()),
            "enc" => Some(Self::enc()),
            "cms" => Some(Self::cms()),
            _ => None,
        }
    }

    pub fn s_client(connect: &str) -> Self {
        Self {
            kind: SubCommandKind::SClient,
            name: "s_client",
            fixed_args: vec![
                "-connect".to_string(), connect.to_string(),
                "-no-interactive".to_string(),
            ],
            stdin_input: Some("Q\n"),
            excluded_flags: vec![
                "-help", "-ssl_config", "-unix", "-keylogfile", "-writerand",
                "-rand", "-msgfile", "-sess_out", "-sess_in", "-early_data",
                "-cert_chain", "-CAstore", "-CRL", "-pass",
                "-provider-path", "-provider", "-provparam", "-propquery",
                "-xkey", "-xcert", "-xchain", "-requestCAfile",
                "-expected-rpks", "-psk_session",
                "-chainCAfile", "-chainCApath", "-chainCAstore",
                "-verifyCAfile", "-verifyCApath", "-verifyCAstore",
                "-xchain_build", "-xcertform", "-xkeyform",
            ],
            needs_input_files: false,
            description: "TLS client handshake fuzzing",
        }
    }

    pub fn x509() -> Self {
        Self {
            kind: SubCommandKind::X509,
            name: "x509",
            fixed_args: vec!["-noout".to_string()],
            stdin_input: None,
            excluded_flags: vec![
                "-help", "-out", "-writerand", "-rand",
                "-provider-path", "-provider", "-provparam", "-propquery",
                "-key", "-signkey", "-CA", "-CAkey", "-CAserial", "-CAcreateserial",
                "-new", "-x509toreq",
            ],
            needs_input_files: true,
            description: "X.509 certificate parsing and display",
        }
    }

    pub fn asn1parse() -> Self {
        Self {
            kind: SubCommandKind::Asn1parse,
            name: "asn1parse",
            fixed_args: vec![],
            stdin_input: None,
            excluded_flags: vec![
                "-help", "-out", "-writerand", "-rand",
                "-provider-path", "-provider", "-provparam", "-propquery",
            ],
            needs_input_files: true,
            description: "ASN.1 structure parsing",
        }
    }

    pub fn verify() -> Self {
        Self {
            kind: SubCommandKind::Verify,
            name: "verify",
            fixed_args: vec![],
            stdin_input: None,
            excluded_flags: vec![
                "-help", "-writerand", "-rand",
                "-provider-path", "-provider", "-provparam", "-propquery",
                "-CAstore",
            ],
            needs_input_files: true,
            description: "Certificate chain verification",
        }
    }

    pub fn req() -> Self {
        Self {
            kind: SubCommandKind::Req,
            name: "req",
            fixed_args: vec!["-noout".to_string()],
            stdin_input: None,
            excluded_flags: vec![
                "-help", "-out", "-outform", "-writerand", "-rand",
                "-provider-path", "-provider", "-provparam", "-propquery",
                "-new", "-newkey", "-keyout", "-config",
            ],
            needs_input_files: true,
            description: "Certificate request parsing",
        }
    }

    pub fn enc() -> Self {
        Self {
            kind: SubCommandKind::Enc,
            name: "enc",
            fixed_args: vec![
                "-d".to_string(),
                "-pass".to_string(), "pass:fuzztest".to_string(),
            ],
            stdin_input: None,
            excluded_flags: vec![
                "-help", "-out", "-writerand", "-rand",
                "-provider-path", "-provider", "-provparam", "-propquery",
                "-kfile",
            ],
            needs_input_files: true,
            description: "Symmetric cipher encrypt/decrypt",
        }
    }

    pub fn cms() -> Self {
        Self {
            kind: SubCommandKind::Cms,
            name: "cms",
            fixed_args: vec![],
            stdin_input: None,
            excluded_flags: vec![
                "-help", "-out", "-config", "-writerand", "-rand",
                "-provider-path", "-provider", "-provparam", "-propquery",
                "-inkey", "-signer", "-recip", "-keyopt", "-certfile",
                "-originator", "-passin",
            ],
            needs_input_files: true,
            description: "CMS/SMIME message operations (sign, verify, encrypt, decrypt, parse)",
        }
    }

    pub fn available() -> Vec<&'static str> {
        vec!["s_client", "x509", "asn1parse", "verify", "req", "enc", "cms"]
    }
}

/// Generate test fixture files for file-based subcommands.
/// Returns a list of file paths created.
pub fn generate_fixtures(fixture_dir: &str) -> Result<Vec<String>, String> {
    use std::fs;
    use std::path::Path;

    let dir = Path::new(fixture_dir);
    fs::create_dir_all(dir).map_err(|e| format!("Failed to create fixture dir: {}", e))?;

    let mut files = Vec::new();

    // 1. Valid self-signed PEM cert (generated via openssl if available, else static)
    let valid_cert = dir.join("valid.pem");
    if !valid_cert.exists() {
        // Use a minimal static self-signed cert
        fs::write(&valid_cert, STATIC_CERT_PEM)
            .map_err(|e| format!("Failed to write valid.pem: {}", e))?;
    }
    files.push(valid_cert.to_string_lossy().to_string());

    // 2. Truncated PEM — cut mid-base64
    let truncated = dir.join("truncated.pem");
    let trunc_content = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALRiMLAh\n";
    fs::write(&truncated, trunc_content)
        .map_err(|e| format!("write truncated.pem: {}", e))?;
    files.push(truncated.to_string_lossy().to_string());

    // 3. Corrupt DER — random-ish bytes with ASN.1 SEQUENCE header
    let corrupt_der = dir.join("corrupt.der");
    let mut der_bytes = vec![0x30, 0x82, 0x01, 0x00]; // SEQUENCE, length 256
    der_bytes.extend_from_slice(&[0xFF; 256]); // garbage payload
    fs::write(&corrupt_der, &der_bytes)
        .map_err(|e| format!("write corrupt.der: {}", e))?;
    files.push(corrupt_der.to_string_lossy().to_string());

    // 4. Empty file
    let empty = dir.join("empty.pem");
    fs::write(&empty, "")
        .map_err(|e| format!("write empty.pem: {}", e))?;
    files.push(empty.to_string_lossy().to_string());

    // 5. Garbage bytes (not valid PEM or DER)
    let garbage = dir.join("garbage.bin");
    let garbage_bytes: Vec<u8> = (0..512).map(|i| (i * 37 + 13) as u8).collect();
    fs::write(&garbage, &garbage_bytes)
        .map_err(|e| format!("write garbage.bin: {}", e))?;
    files.push(garbage.to_string_lossy().to_string());

    // 6. PEM with wrong header (says CERTIFICATE but contains garbage)
    let wrong_header = dir.join("wrong-header.pem");
    fs::write(&wrong_header,
        "-----BEGIN CERTIFICATE-----\nTm90IGEgcmVhbCBjZXJ0aWZpY2F0ZQ==\n-----END CERTIFICATE-----\n")
        .map_err(|e| format!("write wrong-header.pem: {}", e))?;
    files.push(wrong_header.to_string_lossy().to_string());

    // 7. Oversized DER — huge length field
    let oversize = dir.join("oversize.der");
    let mut big_der = vec![0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF]; // SEQUENCE, huge length
    big_der.extend_from_slice(&[0x00; 64]);
    fs::write(&oversize, &big_der)
        .map_err(|e| format!("write oversize.der: {}", e))?;
    files.push(oversize.to_string_lossy().to_string());

    // 8. Nested SEQUENCE depth bomb
    let depth_bomb = dir.join("depth-bomb.der");
    let mut nested = Vec::new();
    for _ in 0..100 {
        nested.push(0x30); // SEQUENCE
        nested.push(0x80); // indefinite length
    }
    nested.extend_from_slice(&[0x00, 0x00]); // end-of-contents
    fs::write(&depth_bomb, &nested)
        .map_err(|e| format!("write depth-bomb.der: {}", e))?;
    files.push(depth_bomb.to_string_lossy().to_string());

    // 9. Valid CSR (for req subcommand)
    let valid_csr = dir.join("valid.csr");
    fs::write(&valid_csr, STATIC_CSR_PEM)
        .map_err(|e| format!("write valid.csr: {}", e))?;
    files.push(valid_csr.to_string_lossy().to_string());

    // 10. Encrypted data blob (for enc subcommand)
    let enc_data = dir.join("encrypted.bin");
    // Salted__ header + random bytes (mimics openssl enc output)
    let mut enc_bytes = b"Salted__".to_vec();
    enc_bytes.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // salt
    enc_bytes.extend_from_slice(&[0xAB; 48]); // ciphertext
    fs::write(&enc_data, &enc_bytes)
        .map_err(|e| format!("write encrypted.bin: {}", e))?;
    files.push(enc_data.to_string_lossy().to_string());

    // 11. CMS signed message (SMIME format)
    let cms_signed = dir.join("signed.smime");
    fs::write(&cms_signed, STATIC_CMS_SIGNED)
        .map_err(|e| format!("write signed.smime: {}", e))?;
    files.push(cms_signed.to_string_lossy().to_string());

    // 12. CMS signed message (DER)
    let cms_signed_der = dir.join("signed.cms.der");
    let mut cms_der = vec![0x30, 0x82, 0x01, 0x50]; // SEQUENCE
    // ContentType: signedData (1.2.840.113549.1.7.2)
    cms_der.extend_from_slice(&[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]);
    cms_der.extend_from_slice(&[0xA0, 0x82, 0x01, 0x3F]); // [0] EXPLICIT
    cms_der.extend_from_slice(&[0xFF; 319]); // payload
    fs::write(&cms_signed_der, &cms_der)
        .map_err(|e| format!("write signed.cms.der: {}", e))?;
    files.push(cms_signed_der.to_string_lossy().to_string());

    // 13. CMS enveloped data (corrupt DER)
    let cms_enveloped = dir.join("enveloped.cms.der");
    let mut env_der = vec![0x30, 0x82, 0x01, 0x00]; // SEQUENCE
    // ContentType: envelopedData (1.2.840.113549.1.7.3)
    env_der.extend_from_slice(&[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03]);
    env_der.extend_from_slice(&[0xA0, 0x80]); // [0] EXPLICIT, indefinite
    env_der.extend_from_slice(&[0xAA; 240]); // garbage payload
    env_der.extend_from_slice(&[0x00, 0x00]); // end-of-contents
    fs::write(&cms_enveloped, &env_der)
        .map_err(|e| format!("write enveloped.cms.der: {}", e))?;
    files.push(cms_enveloped.to_string_lossy().to_string());

    // 14. Plain text data (for cms -data_create / -compress)
    let cms_plaintext = dir.join("plaintext.txt");
    fs::write(&cms_plaintext, "This is test data for CMS operations.\nLine 2.\n")
        .map_err(|e| format!("write plaintext.txt: {}", e))?;
    files.push(cms_plaintext.to_string_lossy().to_string());

    // 15. Truncated SMIME message
    let cms_truncated = dir.join("truncated.smime");
    fs::write(&cms_truncated, "MIME-Version: 1.0\nContent-Type: application/pkcs7-mime; smime-type=signed-data\n\nMIIB")
        .map_err(|e| format!("write truncated.smime: {}", e))?;
    files.push(cms_truncated.to_string_lossy().to_string());

    Ok(files)
}

/// A minimal self-signed PEM certificate for testing.
const STATIC_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJALRiMLAhntiFMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNVBAMMCGZ1
enp0ZXN0MB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowEzERMA8GA1UE
AwwIZnV6enRlc3QwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA0Z3VS5JJcds3xf0G
PCVm0HRnMk1LOSFFlqbGMWpwENiOEsEbfJLEITY5ZmRI9iYCnHby2GSXBLHCSVMP
T9m6RQIDAQABM00wSzAdBgNVHQ4EFgQU/YzaKGnp4TGtXa3bXivSkNfh/7MwHwYD
VR0jBBgwFoAU/YzaKGnp4TGtXa3bXivSkNfh/7MwCQYDVR0TBAIwADANBgkqhkiG
9w0BAQsFAANBAA6LhFkFGhAEJQp5yKDz0hfTdD6U0auLMF3HfEsIkWdGa3bFhJTy
+vCk7m+FL9s1MQOKma+FN0YY6H0OQCA=
-----END CERTIFICATE-----
"#;

/// A minimal CSR in PEM format for req subcommand testing.
const STATIC_CSR_PEM: &str = r#"-----BEGIN CERTIFICATE REQUEST-----
MIIBVTCBvwIBADATMREwDwYDVQQDDAhmdXp6dGVzdDBcMA0GCSqGSIb3DQEBAQUA
A0sAMEgCQQDRndVLkklx2zfF/QY8JWbQdGcyTUs5IUWWpsYxanAQ2I4SwRt8ksQh
NjlmZEj2JgKcdvLYZJcEscJJUw9P2bpFAgMBAAGgRzBFBgkqhkiG9w0BCQ4xODA2
MB0GA1UdDgQWBBT9jNooaenhMa1drdteK9KQ1+H/szAJBgNVHRMEAjAAMAoGA1Ud
DwQDAwEAMA0GCSqGSIb3DQEBCwUAA0EADEUhB8LJhb/eNSBwHHmJB2GOnCAjqNkh
mKPFObXKv4pFIlHdWxBIqNVL+tHBCYEwPOTJkJqaBwLyHvJdAMs=
-----END CERTIFICATE REQUEST-----
"#;

/// A minimal CMS signed-data message in SMIME format for testing.
const STATIC_CMS_SIGNED: &str = "MIME-Version: 1.0\r\n\
Content-Disposition: attachment; filename=\"smime.p7m\"\r\n\
Content-Type: application/pkcs7-mime; smime-type=signed-data; name=\"smime.p7m\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
MIIBkTCB+wIJALRiMLAhntiFMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNVBAMMCGZ1\r\n\
enp0ZXN0MB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowEzERMA8GA1UE\r\n\
AwwIZnV6enRlc3QwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA0Z3VS5JJcds3xf0G\r\n\
PCVm0HRnMk1LOSFFlqbGMWpwENiOEsEbfJLEITY5ZmRI9iYCnHby2GSXBLHCSVMP\r\n\
T9m6RQIDAQABM00wSzAdBgNVHQ4EFgQU/YzaKGnp4TGtXa3bXivSkNfh/7MwHwYD\r\n\
VR0jBBgwFoAU/YzaKGnp4TGtXa3bXivSkNfh/7MwCQYDVR0TBAIwADANBgkqhkiG\r\n\
9w0BAQsFAANBAA6LhFkFGhAEJQp5yKDz0hfTdD6U0auLMF3HfEsIkWdGa3bFhJTy\r\n\
+vCk7m+FL9s1MQOKma+FN0YY6H0OQCA=\r\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_name() {
        assert!(SubCommandDef::from_name("s_client").is_some());
        assert!(SubCommandDef::from_name("x509").is_some());
        assert!(SubCommandDef::from_name("asn1parse").is_some());
        assert!(SubCommandDef::from_name("verify").is_some());
        assert!(SubCommandDef::from_name("req").is_some());
        assert!(SubCommandDef::from_name("enc").is_some());
        assert!(SubCommandDef::from_name("cms").is_some());
        assert!(SubCommandDef::from_name("nonexistent").is_none());
    }

    #[test]
    fn test_s_client_has_stdin() {
        let def = SubCommandDef::s_client("localhost:8443");
        assert_eq!(def.stdin_input, Some("Q\n"));
        assert!(!def.needs_input_files);
    }

    #[test]
    fn test_x509_needs_files() {
        let def = SubCommandDef::x509();
        assert!(def.needs_input_files);
        assert!(def.stdin_input.is_none());
    }

    #[test]
    fn test_excluded_flags_per_subcommand() {
        let sc = SubCommandDef::s_client("localhost:8443");
        assert!(sc.excluded_flags.contains(&"-help"));
        assert!(sc.excluded_flags.contains(&"-unix"));

        let x5 = SubCommandDef::x509();
        assert!(x5.excluded_flags.contains(&"-help"));
        assert!(x5.excluded_flags.contains(&"-new"));
        assert!(!x5.excluded_flags.contains(&"-unix")); // s_client-only
    }

    #[test]
    fn test_cms_needs_files_no_stdin() {
        let def = SubCommandDef::cms();
        assert!(def.needs_input_files);
        assert!(def.stdin_input.is_none());
        assert!(def.fixed_args.is_empty());
        assert_eq!(def.kind, SubCommandKind::Cms);
    }

    #[test]
    fn test_cms_excluded_flags() {
        let def = SubCommandDef::cms();
        assert!(def.excluded_flags.contains(&"-help"));
        assert!(def.excluded_flags.contains(&"-out"));
        assert!(def.excluded_flags.contains(&"-inkey"));
        assert!(def.excluded_flags.contains(&"-signer"));
        assert!(def.excluded_flags.contains(&"-recip"));
        // Operation flags should NOT be excluded
        assert!(!def.excluded_flags.contains(&"-sign"));
        assert!(!def.excluded_flags.contains(&"-verify"));
        assert!(!def.excluded_flags.contains(&"-encrypt"));
        assert!(!def.excluded_flags.contains(&"-decrypt"));
        assert!(!def.excluded_flags.contains(&"-cmsout"));
    }

    #[test]
    fn test_available_subcommands() {
        let avail = SubCommandDef::available();
        assert_eq!(avail.len(), 7);
        assert!(avail.contains(&"s_client"));
        assert!(avail.contains(&"x509"));
        assert!(avail.contains(&"cms"));
    }

    #[test]
    fn test_generate_fixtures() {
        let dir = std::env::temp_dir().join("openssl-fuzz-fixtures-test");
        let _ = std::fs::remove_dir_all(&dir);
        let files = generate_fixtures(dir.to_str().unwrap()).unwrap();
        assert!(files.len() >= 15);
        for f in &files {
            assert!(std::path::Path::new(f).exists(), "Missing: {}", f);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
