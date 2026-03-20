use anyhow::Result;
use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub fn generate_finding_script(
    ls_command: &str,
    fitness: f64,
    exit_code: i32,
    signal: Option<i32>,
    notes: &str,
) -> String {
    let mut script = String::new();

    script.push_str("#!/bin/bash\n");
    script.push_str("#\n");
    script.push_str("# ls-fuzzer Finding Report\n");
    script.push_str("#\n");
    script.push_str(&format!("# Fitness Score: {}\n", fitness));
    script.push_str(&format!("# Exit Code: {}\n", exit_code));

    if let Some(sig) = signal {
        script.push_str(&format!("# Signal: {}\n", sig));
    }

    script.push_str(&format!("# Notes: {}\n", notes));
    script.push_str("#\n\n");
    script.push_str(&format!("{}\n", ls_command));

    script
}

pub fn write_finding(
    output_dir: &str,
    generation: usize,
    individual_id: usize,
    ls_command: &str,
    fitness: f64,
    exit_code: i32,
    signal: Option<i32>,
    notes: &str,
) -> Result<String> {
    fs::create_dir_all(output_dir)?;

    let filename = format!(
        "finding-gen{:04}-ind{:04}-fit{:.0}.sh",
        generation, individual_id, fitness
    );

    let filepath = Path::new(output_dir).join(&filename);
    let script_content = generate_finding_script(ls_command, fitness, exit_code, signal, notes);

    fs::write(&filepath, script_content)?;

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

    #[test]
    fn test_script_content() {
        let script = generate_finding_script(
            "ls -la --recursive /tmp",
            100.0,
            -1,
            Some(11),
            "SIGSEGV crash",
        );

        assert!(script.contains("#!/bin/bash"));
        assert!(script.contains("ls-fuzzer Finding Report"));
        assert!(script.contains("Fitness Score: 100"));
        assert!(script.contains("Exit Code: -1"));
        assert!(script.contains("Signal: 11"));
        assert!(script.contains("Notes: SIGSEGV crash"));
        assert!(script.contains("ls -la --recursive /tmp"));
    }

    #[test]
    fn test_script_without_signal() {
        let script = generate_finding_script("ls -l /tmp", 5.0, 2, None, "exit 2");
        assert!(script.contains("Fitness Score: 5"));
        assert!(!script.contains("Signal:"));
    }

    #[test]
    fn test_write_finding_creates_file() {
        let temp_dir = std::env::temp_dir().join("ls-fuzzer-test-findings");
        let temp_dir_str = temp_dir.to_str().unwrap();

        let _ = std::fs::remove_dir_all(&temp_dir);

        let filename = write_finding(
            temp_dir_str,
            3,
            7,
            "ls -laR /tmp",
            42.0,
            0,
            None,
            "Timing anomaly",
        ).unwrap();

        assert_eq!(filename, "finding-gen0003-ind0007-fit42.sh");

        let filepath = temp_dir.join(&filename);
        assert!(filepath.exists());

        let content = std::fs::read_to_string(&filepath).unwrap();
        assert!(content.contains("ls -laR /tmp"));

        #[cfg(unix)]
        {
            let metadata = std::fs::metadata(&filepath).unwrap();
            let permissions = metadata.permissions();
            assert_eq!(permissions.mode() & 0o111, 0o111);
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
