use std::process::Command;

#[test]
fn test_protocol_registry_coverage() {
    use curl_fuzzer::protocol::ProtocolRegistry;
    let registry = ProtocolRegistry::default();

    let expected = vec![
        "http", "https", "ftp", "ftps", "smtp", "smtps",
        "imap", "imaps", "pop3", "pop3s", "gopher", "gophers",
        "dict", "mqtt", "mqtts", "tftp", "telnet", "ws", "wss", "file",
    ];

    for proto in &expected {
        assert!(registry.get(proto).is_some(), "Missing protocol: {}", proto);
    }
    assert_eq!(registry.protocols.len(), expected.len());
}

#[test]
fn test_cli_help() {
    let output = Command::new("cargo")
        .args(&["run", "-p", "curl-fuzzer", "--", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify output contains subcommand names
    assert!(stdout.contains("run") || stdout.contains("Run"));
    assert!(stdout.contains("replay") || stdout.contains("Replay"));
    assert!(stdout.contains("report") || stdout.contains("Report"));
}

#[test]
fn test_dry_run() {
    // Run fuzzer with minimal settings for a quick test
    let output = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "curl-fuzzer",
            "--",
            "run",
            "--no-servers",
            "--generations",
            "1",
            "--population-size",
            "3",
        ])
        .output()
        .expect("Failed to execute command");

    // Verify it doesn't panic - check that it ran
    // We don't check exit code because it might fail due to missing curl or config
    // but it shouldn't panic
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Make sure there's no panic message
    assert!(!stderr.contains("panicked at"));
}
