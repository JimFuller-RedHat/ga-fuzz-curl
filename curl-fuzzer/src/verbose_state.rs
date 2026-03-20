/// Analyze curl --verbose output for state machine anomalies.
/// Returns a score from 0.0 (normal) to 1.0+ (anomalous).
/// Also returns a list of anomaly labels found.

#[derive(Debug, Default)]
pub struct VerboseState {
    pub connect_count: usize,
    pub tls_handshake_starts: usize,
    pub tls_handshake_completions: usize,
    pub requests_sent: usize,
    pub responses_received: usize,
    pub connection_resets: usize,
    pub re_resolved: usize,
    pub state_lines: usize,
    pub connection_left_intact: usize,
    pub connection_closed: usize,
    pub http2_streams: usize,
    pub retries: usize,
}

pub struct VerboseAnalysis {
    pub anomaly_score: f64,
    pub labels: Vec<&'static str>,
}

pub fn analyze_verbose(stderr: &str) -> VerboseAnalysis {
    let state = parse_verbose(stderr);
    let mut score = 0.0;
    let mut labels = Vec::new();

    // 1. Multiple connections (unexpected reconnects)
    if state.connect_count > 1 {
        let s = (state.connect_count - 1) as f64 * 0.3;
        score += s;
        labels.push("multi_connect");
    }

    // 2. Partial TLS handshake (started but not completed)
    if state.tls_handshake_starts > 0 && state.tls_handshake_completions < state.tls_handshake_starts {
        let incomplete = state.tls_handshake_starts - state.tls_handshake_completions;
        score += incomplete as f64 * 0.5;
        labels.push("partial_tls");
    }

    // 3. Request sent but no response
    if state.requests_sent > 0 && state.responses_received == 0 {
        score += 0.4;
        labels.push("no_response");
    }

    // 4. More responses than requests (protocol confusion)
    if state.responses_received > state.requests_sent && state.requests_sent > 0 {
        score += 0.6;
        labels.push("extra_responses");
    }

    // 5. Connection reset detected
    if state.connection_resets > 0 {
        score += state.connection_resets as f64 * 0.2;
        labels.push("conn_reset");
    }

    // 6. Re-resolution of hostname (DNS rebinding-like)
    if state.re_resolved > 0 {
        score += state.re_resolved as f64 * 0.3;
        labels.push("re_resolved");
    }

    // 7. Abnormally high state line count (state machine spinning)
    if state.state_lines > 50 {
        score += ((state.state_lines - 50) as f64 / 50.0).min(1.0);
        labels.push("state_flood");
    }

    // 8. Connection not cleanly closed (no "left intact" or "closed")
    if state.connect_count > 0 && state.connection_left_intact == 0 && state.connection_closed == 0 {
        score += 0.2;
        labels.push("unclean_close");
    }

    // 9. HTTP/2 stream anomaly (many streams)
    if state.http2_streams > 3 {
        score += (state.http2_streams - 3) as f64 * 0.2;
        labels.push("h2_streams");
    }

    // 10. Retry detected
    if state.retries > 0 {
        score += state.retries as f64 * 0.15;
        labels.push("retry");
    }

    VerboseAnalysis { anomaly_score: score, labels }
}

fn parse_verbose(stderr: &str) -> VerboseState {
    let mut state = VerboseState::default();

    for line in stderr.lines() {
        let trimmed = line.trim();

        // Count info/state lines
        if trimmed.starts_with("* ") {
            state.state_lines += 1;
            let msg = &trimmed[2..];

            if msg.starts_with("Connected to ") || msg.starts_with("connect to ") {
                state.connect_count += 1;
            }
            if msg.contains("TLS handshake") || msg.contains("SSL connection") {
                if msg.contains("(OUT)") || msg.contains("Client hello") {
                    state.tls_handshake_starts += 1;
                }
            }
            if msg.contains("SSL certificate verify ok")
                || msg.contains("SSL connection using")
                || msg.contains("ALPN: server accepted")
            {
                state.tls_handshake_completions += 1;
            }
            if msg.contains("Connection reset") || msg.contains("connection reset") {
                state.connection_resets += 1;
            }
            if msg.contains("Re-using") || msg.contains("Re-resolve") || msg.contains("re-resolve") {
                state.re_resolved += 1;
            }
            if msg.contains("left intact") {
                state.connection_left_intact += 1;
            }
            if msg.contains("Closing connection") {
                state.connection_closed += 1;
            }
            if msg.contains("Using Stream ID") || msg.contains("stream ") {
                state.http2_streams += 1;
            }
            if msg.contains("retry") || msg.contains("Retry") {
                state.retries += 1;
            }
        }

        // Request headers sent
        if trimmed.starts_with("> ") {
            // First request line (GET, POST, etc.)
            let header = &trimmed[2..];
            if header.starts_with("GET ")
                || header.starts_with("POST ")
                || header.starts_with("PUT ")
                || header.starts_with("HEAD ")
                || header.starts_with("DELETE ")
                || header.starts_with("PATCH ")
                || header.starts_with("OPTIONS ")
                || header.starts_with("CONNECT ")
            {
                state.requests_sent += 1;
            }
        }

        // Response headers received
        if trimmed.starts_with("< ") {
            let header = &trimmed[2..];
            if header.starts_with("HTTP/") {
                state.responses_received += 1;
            }
        }
    }

    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_http_no_anomaly() {
        let stderr = "\
* Trying 127.0.0.1:8080...
* Connected to localhost (127.0.0.1) port 8080
> GET / HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/8.19.1
> Accept: */*
>
< HTTP/1.1 200 OK
< Content-Length: 13
<
* Connection #0 to host localhost left intact";
        let analysis = analyze_verbose(stderr);
        assert!(analysis.anomaly_score < 0.01, "Normal HTTP should score ~0, got {}", analysis.anomaly_score);
        assert!(analysis.labels.is_empty());
    }

    #[test]
    fn test_multi_connect_detected() {
        let stderr = "\
* Trying 127.0.0.1:8080...
* Connected to localhost (127.0.0.1) port 8080
* Connection reset
* Trying 127.0.0.1:8080...
* Connected to localhost (127.0.0.1) port 8080
> GET / HTTP/1.1
< HTTP/1.1 200 OK
* Connection #0 to host localhost left intact";
        let analysis = analyze_verbose(stderr);
        assert!(analysis.labels.contains(&"multi_connect"));
        assert!(analysis.labels.contains(&"conn_reset"));
        assert!(analysis.anomaly_score > 0.3);
    }

    #[test]
    fn test_partial_tls_handshake() {
        let stderr = "\
* Trying 127.0.0.1:443...
* Connected to localhost (127.0.0.1) port 443
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* Closing connection";
        let analysis = analyze_verbose(stderr);
        assert!(analysis.labels.contains(&"partial_tls"));
        assert!(analysis.anomaly_score >= 0.5);
    }

    #[test]
    fn test_complete_tls_no_partial() {
        let stderr = "\
* Trying 127.0.0.1:443...
* Connected to localhost (127.0.0.1) port 443
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN: server accepted h2
> GET / HTTP/2
< HTTP/2 200
* Connection #0 to host localhost left intact";
        let analysis = analyze_verbose(stderr);
        assert!(!analysis.labels.contains(&"partial_tls"));
    }

    #[test]
    fn test_request_no_response() {
        let stderr = "\
* Trying 127.0.0.1:8080...
* Connected to localhost (127.0.0.1) port 8080
> GET / HTTP/1.1
> Host: localhost
* Closing connection";
        let analysis = analyze_verbose(stderr);
        assert!(analysis.labels.contains(&"no_response"));
    }

    #[test]
    fn test_state_flood() {
        let mut lines = vec!["* Trying 127.0.0.1:8080...", "* Connected to localhost (127.0.0.1) port 8080"];
        for _i in 0..60 {
            lines.push("* some state transition");
        }
        lines.push("> GET / HTTP/1.1");
        lines.push("< HTTP/1.1 200 OK");
        lines.push("* Connection #0 to host localhost left intact");
        let stderr = lines.join("\n");
        let analysis = analyze_verbose(&stderr);
        assert!(analysis.labels.contains(&"state_flood"));
    }

    #[test]
    fn test_extra_responses() {
        let stderr = "\
* Connected to localhost (127.0.0.1) port 8080
> GET / HTTP/1.1
< HTTP/1.1 301 Moved
< HTTP/1.1 200 OK
* Connection #0 to host localhost left intact";
        let analysis = analyze_verbose(stderr);
        assert!(analysis.labels.contains(&"extra_responses"));
    }

    #[test]
    fn test_empty_stderr() {
        let analysis = analyze_verbose("");
        assert!(analysis.anomaly_score < 0.01);
        assert!(analysis.labels.is_empty());
    }

    #[test]
    fn test_non_verbose_stderr_ignored() {
        let stderr = "curl: (7) Failed to connect to localhost port 8080: Connection refused";
        let analysis = analyze_verbose(stderr);
        // No verbose prefixes, so no state tracked
        assert!(analysis.anomaly_score < 0.01);
    }
}
