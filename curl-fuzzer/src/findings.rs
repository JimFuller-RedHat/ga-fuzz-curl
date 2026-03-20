use anyhow::Result;
use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub fn generate_finding_script(
    curl_command: &str,
    fitness: f64,
    exit_code: i32,
    signal: Option<i32>,
    notes: &str,
) -> String {
    let mut script = String::new();

    script.push_str("#!/bin/bash\n");
    script.push_str("#\n");
    script.push_str("# Fuzzer Finding Report\n");
    script.push_str("#\n");
    script.push_str(&format!("# Fitness Score: {}\n", fitness));
    script.push_str(&format!("# Exit Code: {}\n", exit_code));

    if let Some(sig) = signal {
        script.push_str(&format!("# Signal: {}\n", sig));
    }

    script.push_str(&format!("# Notes: {}\n", notes));
    script.push_str("#\n\n");
    script.push_str(&format!("{}\n", curl_command));

    script
}

pub fn write_finding(
    output_dir: &str,
    generation: usize,
    individual_id: usize,
    curl_command: &str,
    fitness: f64,
    exit_code: i32,
    signal: Option<i32>,
    notes: &str,
) -> Result<String> {
    // Create output directory if it doesn't exist
    fs::create_dir_all(output_dir)?;

    // Generate filename
    let filename = format!(
        "finding-gen{:04}-ind{:04}-fit{:.0}.sh",
        generation, individual_id, fitness
    );

    let filepath = Path::new(output_dir).join(&filename);

    // Generate script content
    let script_content = generate_finding_script(curl_command, fitness, exit_code, signal, notes);

    // Write the file
    fs::write(&filepath, script_content)?;

    // Make file executable on Unix
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&filepath)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&filepath, perms)?;
    }

    Ok(filename)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_script_content_contains_expected_fields() {
        let script = generate_finding_script(
            "curl -X GET http://example.com",
            100.0,
            0,
            Some(11),
            "Test finding",
        );

        assert!(script.contains("#!/bin/bash"));
        assert!(script.contains("Fitness Score: 100"));
        assert!(script.contains("Exit Code: 0"));
        assert!(script.contains("Signal: 11"));
        assert!(script.contains("Notes: Test finding"));
        assert!(script.contains("curl -X GET http://example.com"));
    }

    #[test]
    fn test_script_without_signal() {
        let script = generate_finding_script(
            "curl http://test.com",
            50.0,
            1,
            None,
            "No signal",
        );

        assert!(script.contains("Fitness Score: 50"));
        assert!(script.contains("Exit Code: 1"));
        assert!(!script.contains("Signal:"));
        assert!(script.contains("Notes: No signal"));
    }

    #[test]
    fn test_write_finding_creates_file() {
        let temp_dir = std::env::temp_dir().join("curl-fuzzer-test-findings");
        let temp_dir_str = temp_dir.to_str().unwrap();

        // Clean up any existing test directory
        let _ = fs::remove_dir_all(&temp_dir);

        let filename = write_finding(
            temp_dir_str,
            5,
            12,
            "curl -v http://example.com",
            75.0,
            0,
            None,
            "Interesting finding",
        ).unwrap();

        assert_eq!(filename, "finding-gen0005-ind0012-fit75.sh");

        let filepath = temp_dir.join(&filename);
        assert!(filepath.exists());

        let content = fs::read_to_string(&filepath).unwrap();
        assert!(content.contains("curl -v http://example.com"));
        assert!(content.contains("Fitness Score: 75"));

        // Check if executable on Unix
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&filepath).unwrap();
            let permissions = metadata.permissions();
            assert_eq!(permissions.mode() & 0o111, 0o111); // Check executable bits
        }

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
