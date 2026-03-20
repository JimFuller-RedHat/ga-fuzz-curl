/// Analyze openssl s_client output for TLS handshake anomalies.
/// Parses stdout (connection info) and stderr (diagnostics) to detect
/// protocol downgrades, incomplete handshakes, unexpected ciphers, etc.

#[derive(Debug, Default)]
pub struct TlsState {
    pub handshake_complete: bool,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub verify_return_code: Option<i32>,
    pub cert_chain_depth: usize,
    pub renegotiation_seen: bool,
    pub session_reused: bool,
    pub alert_received: bool,
    pub alert_descriptions: Vec<String>,
    pub connection_established: bool,
    pub ssl_error_seen: bool,
    pub verify_error_seen: bool,
}

pub struct TlsAnalysis {
    pub anomaly_score: f64,
    #[allow(dead_code)]
    pub labels: Vec<&'static str>,
}

/// Parse s_client stdout + stderr into TLS state
pub fn parse_tls_output(stdout: &str, stderr: &str) -> TlsState {
    let mut state = TlsState::default();
    let combined = format!("{}\n{}", stdout, stderr);

    for line in combined.lines() {
        let trimmed = line.trim();

        // Handshake completion
        if trimmed.starts_with("SSL handshake has read") {
            state.handshake_complete = true;
        }

        // Connection established
        if trimmed.starts_with("CONNECTED(") {
            state.connection_established = true;
        }

        // Protocol version (e.g., "Protocol  : TLSv1.3")
        if let Some(rest) = trimmed.strip_prefix("Protocol") {
            let rest = rest.trim().trim_start_matches(':').trim();
            if !rest.is_empty() {
                state.protocol_version = Some(rest.to_string());
            }
        }

        // Cipher suite (e.g., "Cipher    : TLS_AES_256_GCM_SHA384")
        if trimmed.starts_with("Cipher") && trimmed.contains(':') && !trimmed.contains("Ciphers") {
            if let Some(cipher) = trimmed.split(':').nth(1) {
                let c = cipher.trim();
                if !c.is_empty() && c != "0000" {
                    state.cipher_suite = Some(c.to_string());
                }
            }
        }

        // Verify return code
        if let Some(rest) = trimmed.strip_prefix("Verify return code:") {
            if let Some(code_str) = rest.trim().split_whitespace().next() {
                if let Ok(code) = code_str.parse::<i32>() {
                    state.verify_return_code = Some(code);
                }
            }
        }

        // Certificate chain depth
        if trimmed.contains("depth=") || trimmed.starts_with(" ") && trimmed.contains("s:") {
            if let Some(d) = trimmed.strip_prefix("depth=") {
                if let Some(depth_str) = d.split_whitespace().next() {
                    if let Ok(depth) = depth_str.parse::<usize>() {
                        if depth + 1 > state.cert_chain_depth {
                            state.cert_chain_depth = depth + 1;
                        }
                    }
                }
            }
        }

        // Renegotiation
        if trimmed.contains("RENEGOTIATING") || trimmed.contains("renegotiat") {
            state.renegotiation_seen = true;
        }

        // Session reuse
        if trimmed.contains("Reused,") || trimmed.contains("Session-ID:") && trimmed.contains("(reused)") {
            state.session_reused = true;
        }

        // TLS alerts
        if trimmed.contains("SSL alert") || trimmed.contains("tlsv1 alert") || trimmed.contains("sslv3 alert") {
            state.alert_received = true;
            state.alert_descriptions.push(trimmed.to_string());
        }

        // SSL errors
        if trimmed.contains("SSL_ERROR") || trimmed.contains("ssl handshake failure")
            || trimmed.contains("error:") && (trimmed.contains("SSL") || trimmed.contains("ssl"))
        {
            state.ssl_error_seen = true;
        }

        // Verify errors
        if trimmed.contains("verify error:") {
            state.verify_error_seen = true;
        }
    }

    state
}

/// Score TLS state anomalies. Returns 0.0 for normal, higher for more anomalous.
pub fn analyze_tls(stdout: &str, stderr: &str) -> TlsAnalysis {
    let state = parse_tls_output(stdout, stderr);
    let mut score = 0.0;
    let mut labels = Vec::new();

    // 1. Connected but handshake didn't complete
    if state.connection_established && !state.handshake_complete {
        score += 0.6;
        labels.push("incomplete_handshake");
    }

    // 2. Handshake complete but no cipher (shouldn't happen)
    if state.handshake_complete && state.cipher_suite.is_none() {
        score += 0.5;
        labels.push("no_cipher");
    }

    // 3. NULL or EXPORT cipher selected
    if let Some(ref cipher) = state.cipher_suite {
        let c = cipher.to_uppercase();
        if c.contains("NULL") || c.contains("EXPORT") || c.contains("ANON") || c == "0000" {
            score += 0.8;
            labels.push("weak_cipher");
        }
    }

    // 4. Protocol downgrade — got SSLv3 or TLSv1.0
    if let Some(ref proto) = state.protocol_version {
        let p = proto.to_lowercase();
        if p.contains("sslv2") || p.contains("sslv3") {
            score += 0.7;
            labels.push("legacy_protocol");
        } else if p.contains("tlsv1") && !p.contains("tlsv1.2") && !p.contains("tlsv1.3") {
            score += 0.4;
            labels.push("old_tls");
        }
    }

    // 5. Renegotiation detected
    if state.renegotiation_seen {
        score += 0.5;
        labels.push("renegotiation");
    }

    // 6. TLS alert received (not just connection refused)
    if state.alert_received {
        // Some alerts are more interesting than others
        let interesting_alerts = ["internal_error", "decode_error", "illegal_parameter",
            "bad_record_mac", "record_overflow", "decompression_failure",
            "unexpected_message", "bad_certificate"];
        let has_interesting = state.alert_descriptions.iter().any(|a| {
            let al = a.to_lowercase();
            interesting_alerts.iter().any(|ia| al.contains(ia))
        });
        if has_interesting {
            score += 0.6;
            labels.push("interesting_alert");
        } else {
            score += 0.2;
            labels.push("tls_alert");
        }
    }

    // 7. Certificate verification failure (non-self-signed — code != 18 and != 19)
    if let Some(code) = state.verify_return_code {
        match code {
            0 => {} // OK
            18 | 19 | 20 | 21 => {} // self-signed / untrusted — expected with test certs
            2 | 3 | 10 | 12 | 23 | 24 | 26 => {
                // CRL errors, cert revoked, chain too long, invalid purpose
                score += 0.5;
                labels.push("cert_verify_anomaly");
            }
            _ => {
                score += 0.3;
                labels.push("cert_verify_error");
            }
        }
    }

    // 8. Connected but got SSL error (internal state issue)
    if state.connection_established && state.ssl_error_seen && !state.alert_received {
        score += 0.4;
        labels.push("ssl_internal_error");
    }

    // 9. No connection established at all (total failure before TCP)
    if !state.connection_established && !state.ssl_error_seen {
        // Not very interesting — just couldn't connect
    }

    TlsAnalysis {
        anomaly_score: score,
        labels,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_handshake() {
        let stdout = "\
CONNECTED(00000003)
depth=0 CN = localhost
---
Certificate chain
 0 s:CN = localhost
   i:CN = localhost
---
SSL handshake has read 1234 bytes and written 456 bytes
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol  : TLSv1.3
Cipher    : TLS_AES_256_GCM_SHA384
Verify return code: 18 (self-signed certificate)
";
        let analysis = analyze_tls(stdout, "");
        assert!(analysis.anomaly_score < 0.1, "Normal handshake should score low, got {}", analysis.anomaly_score);
        assert!(analysis.labels.is_empty());
    }

    #[test]
    fn test_incomplete_handshake() {
        let stdout = "CONNECTED(00000003)\n";
        let stderr = "error: ssl handshake failure\n";
        let analysis = analyze_tls(stdout, stderr);
        assert!(analysis.anomaly_score >= 0.6);
        assert!(analysis.labels.contains(&"incomplete_handshake"));
    }

    #[test]
    fn test_legacy_protocol() {
        let stdout = "\
CONNECTED(00000003)
SSL handshake has read 1234 bytes
Protocol  : SSLv3
Cipher    : DES-CBC3-SHA
Verify return code: 0 (ok)
";
        let analysis = analyze_tls(stdout, "");
        assert!(analysis.labels.contains(&"legacy_protocol"));
        assert!(analysis.anomaly_score >= 0.7);
    }

    #[test]
    fn test_weak_cipher() {
        let stdout = "\
CONNECTED(00000003)
SSL handshake has read 1234 bytes
Protocol  : TLSv1.2
Cipher    : NULL-SHA256
Verify return code: 0 (ok)
";
        let analysis = analyze_tls(stdout, "");
        assert!(analysis.labels.contains(&"weak_cipher"));
    }

    #[test]
    fn test_renegotiation() {
        let stdout = "\
CONNECTED(00000003)
SSL handshake has read 1234 bytes
RENEGOTIATING
depth=0 CN = localhost
Protocol  : TLSv1.2
Cipher    : AES256-SHA
Verify return code: 0 (ok)
";
        let analysis = analyze_tls(stdout, "");
        assert!(analysis.labels.contains(&"renegotiation"));
    }

    #[test]
    fn test_interesting_alert() {
        let stdout = "CONNECTED(00000003)\n";
        let stderr = "SSL alert: sslv3 alert decode_error\n";
        let analysis = analyze_tls(stdout, stderr);
        assert!(analysis.labels.contains(&"interesting_alert"));
        assert!(analysis.anomaly_score >= 0.6);
    }

    #[test]
    fn test_cert_verify_anomaly() {
        let stdout = "\
CONNECTED(00000003)
SSL handshake has read 1234 bytes
Protocol  : TLSv1.3
Cipher    : TLS_AES_256_GCM_SHA384
Verify return code: 23 (certificate revoked)
";
        let analysis = analyze_tls(stdout, "");
        assert!(analysis.labels.contains(&"cert_verify_anomaly"));
    }

    #[test]
    fn test_multiple_anomalies_stack() {
        let stdout = "\
CONNECTED(00000003)
Protocol  : SSLv3
Cipher    : NULL-SHA
RENEGOTIATING
";
        let stderr = "SSL alert: sslv3 alert internal_error\n";
        let analysis = analyze_tls(stdout, stderr);
        // incomplete_handshake + legacy_protocol + weak_cipher + renegotiation + interesting_alert
        assert!(analysis.anomaly_score >= 2.0);
        assert!(analysis.labels.len() >= 3);
    }

    #[test]
    fn test_parse_protocol_version() {
        let state = parse_tls_output("Protocol  : TLSv1.3\n", "");
        assert_eq!(state.protocol_version.as_deref(), Some("TLSv1.3"));
    }

    #[test]
    fn test_parse_cipher() {
        let state = parse_tls_output("Cipher    : TLS_AES_256_GCM_SHA384\n", "");
        assert_eq!(state.cipher_suite.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
    }
}
