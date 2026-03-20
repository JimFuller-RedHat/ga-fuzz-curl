use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Parsed timing and transfer metadata from curl's -w %{json} output.
#[derive(Debug, Clone, Default)]
pub struct CurlWriteOut {
    pub http_code: Option<u16>,
    pub num_connects: Option<u32>,
    pub num_redirects: Option<u32>,
    pub redirect_url: Option<String>,
    pub size_download: Option<u64>,
    pub size_request: Option<u64>,
    pub size_header: Option<u64>,
    pub time_namelookup: Option<f64>,
    pub time_connect: Option<f64>,
    pub time_appconnect: Option<f64>,
    pub time_starttransfer: Option<f64>,
    pub time_total: Option<f64>,
    pub scheme: Option<String>,
}

pub struct CoverageConfig {
    pub source_root: String,
    pub strip_count: u32,
}

#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub http_status: Option<u16>,
    pub peak_rss_kb: Option<u64>,
    pub cpu_user_ms: Option<u64>,
    pub cpu_sys_ms: Option<u64>,
    pub core_dumped: bool,
    pub timed_out: bool,
    pub max_fd_count: Option<u32>,
    pub server_malformation: Option<String>,
    pub write_out: CurlWriteOut,
    pub coverage_edges: Vec<u64>,  // empty when coverage disabled or collection failed
}

impl ExecutionResult {
    #[allow(dead_code)]
    pub fn crashed(&self) -> Option<i32> {
        self.signal
    }
}

pub fn build_injected_args(
    fuzzed_args: &[String],
    timeout_ms: u64,
    is_tls: bool,
    is_blocking: bool,
    blocking_timeout_s: u64,
    cert_path: Option<&str>,
) -> Vec<String> {
    let mut args: Vec<String> = fuzzed_args.to_vec();

    let timeout_secs = if is_blocking {
        blocking_timeout_s
    } else {
        (timeout_ms / 1000).max(1)
    };
    let connect_timeout = (timeout_secs / 3).max(1);

    args.push("--max-time".into());
    args.push(timeout_secs.to_string());
    args.push("--connect-timeout".into());
    args.push(connect_timeout.to_string());

    if is_tls {
        if let Some(cert) = cert_path {
            args.push("--cacert".into());
            args.push(cert.to_string());
        }
    }

    args.push("-w".into());
    args.push("\n__CURL_JSON__\n%{json}".into());
    args.push("-s".into());
    args.push("--verbose".into());

    args
}

pub fn execute_curl(
    curl_path: &str,
    args: &[String],
    timeout_ms: u64,
    is_tls: bool,
    is_blocking: bool,
    blocking_timeout_s: u64,
    cert_path: Option<&str>,
    coverage: Option<&CoverageConfig>,
) -> Result<ExecutionResult, String> {
    let start = Instant::now();

    let injected = build_injected_args(args, timeout_ms, is_tls, is_blocking, blocking_timeout_s, cert_path);

    // Create a temp directory for curl to run in, so any files it creates
    // (e.g. from -O, --output, --dump-header) don't pollute the working directory
    let tmp_dir = tempfile::tempdir()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    // Create a separate gcda dir for coverage data (distinct from tmp_dir for curl outputs)
    let gcda_dir = if coverage.is_some() {
        Some(tempfile::tempdir()
            .map_err(|e| format!("Failed to create gcda dir: {}", e))?)
    } else {
        None
    };

    // Build command with injected args (includes fuzzed args + our injected timeouts/options)
    let mut cmd = Command::new(curl_path);
    cmd.current_dir(tmp_dir.path());

    if let (Some(ref gcda), Some(cfg)) = (&gcda_dir, coverage) {
        cmd.env("GCOV_PREFIX", gcda.path());
        cmd.env("GCOV_PREFIX_STRIP", cfg.strip_count.to_string());
    }

    cmd.args(&injected);

    // Spawn the child process so we can use wait4 for resource usage
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to execute curl: {}", e))?;

    // Spawn a watchdog thread that kills the child after timeout_ms + 2s grace period.
    // This is a hard process-level backstop independent of curl's --max-time.
    let child_pid = child.id();
    let max_fd = Arc::new(AtomicU32::new(0));
    let max_fd_clone = Arc::clone(&max_fd);
    let killed = Arc::new(AtomicBool::new(false));
    let killed_clone = Arc::clone(&killed);
    let hard_timeout = Duration::from_millis(timeout_ms + 2000);
    let watchdog = std::thread::spawn(move || {
        let start = Instant::now();
        let proc_fd_path = format!("/proc/{}/fd", child_pid);
        while start.elapsed() < hard_timeout {
            // Sample FD count
            if let Ok(entries) = std::fs::read_dir(&proc_fd_path) {
                let count = entries.count() as u32;
                max_fd_clone.fetch_max(count, Ordering::Relaxed);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // Process may already be gone — that's fine, kill will fail harmlessly
        #[cfg(unix)]
        unsafe {
            libc::kill(child_pid as libc::pid_t, libc::SIGKILL);
        }
        killed_clone.store(true, Ordering::SeqCst);
    });

    // Read stdout/stderr (blocks until child closes pipes, i.e. exits or is killed)
    let (stdout_bytes, stderr_bytes) = {
        use std::io::Read;
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        if let Some(ref mut out) = child.stdout {
            let _ = out.read_to_end(&mut stdout_buf);
        }
        if let Some(ref mut err) = child.stderr {
            let _ = err.read_to_end(&mut stderr_buf);
        }
        (stdout_buf, stderr_buf)
    };

    // Wait and collect resource usage
    #[cfg(unix)]
    let (exit_code, signal, peak_rss_kb, cpu_user_ms, cpu_sys_ms, core_dumped) = {
        let pid = child.id() as libc::pid_t;
        let mut status: libc::c_int = 0;
        let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };

        let wait_result = unsafe {
            libc::wait4(pid, &mut status, 0, &mut rusage)
        };

        if wait_result < 0 {
            // Fallback to normal wait
            use std::os::unix::process::ExitStatusExt;
            let output_status = child.wait().map_err(|e| format!("wait failed: {}", e))?;
            (output_status.code().unwrap_or(-1), output_status.signal(), None, None, None, false)
        } else {
            let exit_code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -1
            };
            let sig = if libc::WIFSIGNALED(status) {
                Some(libc::WTERMSIG(status))
            } else {
                None
            };
            // WCOREDUMP: bit 0x80 of status when signaled
            let dumped = libc::WIFSIGNALED(status) && (status & 0x80) != 0;
            // ru_maxrss is in KB on Linux
            let rss = rusage.ru_maxrss as u64;
            let user_ms = (rusage.ru_utime.tv_sec as u64) * 1000
                + (rusage.ru_utime.tv_usec as u64) / 1000;
            let sys_ms = (rusage.ru_stime.tv_sec as u64) * 1000
                + (rusage.ru_stime.tv_usec as u64) / 1000;
            (exit_code, sig, Some(rss), Some(user_ms), Some(sys_ms), dumped)
        }
    };

    #[cfg(not(unix))]
    let (exit_code, signal, peak_rss_kb, cpu_user_ms, cpu_sys_ms, core_dumped) = {
        let output_status = child.wait().map_err(|e| format!("wait failed: {}", e))?;
        (output_status.code().unwrap_or(-1), None::<i32>, None, None, None, false)
    };

    // Check if the watchdog killed the process
    let timed_out = killed.load(Ordering::SeqCst);
    let _ = watchdog.join();

    let max_fd_count = {
        let v = max_fd.load(Ordering::Relaxed);
        if v > 0 { Some(v) } else { None }
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    let coverage_edges = match (&gcda_dir, coverage) {
        (Some(gcda), Some(cfg)) => {
            crate::coverage::collect_coverage(gcda.path(), std::path::Path::new(&cfg.source_root))
        }
        _ => Vec::new(),
    };

    let stdout_raw = String::from_utf8_lossy(&stdout_bytes).to_string();
    let stderr = String::from_utf8_lossy(&stderr_bytes).to_string();

    let (stdout, write_out) = extract_write_out(&stdout_raw);
    let http_status = write_out.http_code;

    Ok(ExecutionResult {
        exit_code,
        signal,
        stdout,
        stderr,
        duration_ms,
        http_status,
        peak_rss_kb,
        cpu_user_ms,
        cpu_sys_ms,
        core_dumped,
        timed_out,
        max_fd_count,
        server_malformation: None,
        write_out,
        coverage_edges,
    })
}

/// Extract the JSON write-out blob from stdout, separated by the __CURL_JSON__ marker.
/// Returns the cleaned stdout (without the JSON) and the parsed CurlWriteOut.
fn extract_write_out(stdout: &str) -> (String, CurlWriteOut) {
    if let Some(marker_pos) = stdout.rfind("__CURL_JSON__\n") {
        let body = &stdout[..marker_pos];
        // Strip trailing newline before marker
        let body = body.strip_suffix('\n').unwrap_or(body);
        let json_str = &stdout[marker_pos + "__CURL_JSON__\n".len()..];
        let write_out = parse_write_out_json(json_str);
        (body.to_string(), write_out)
    } else {
        // Fallback: try parsing last line as plain http_code (backwards compat)
        let lines: Vec<&str> = stdout.lines().collect();
        if let Some(last) = lines.last() {
            if let Ok(status) = last.trim().parse::<u16>() {
                let remaining = &lines[..lines.len() - 1];
                return (remaining.join("\n"), CurlWriteOut {
                    http_code: Some(status),
                    ..Default::default()
                });
            }
        }
        (stdout.to_string(), CurlWriteOut::default())
    }
}

fn parse_write_out_json(json_str: &str) -> CurlWriteOut {
    let v: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return CurlWriteOut::default(),
    };

    let http_code = v.get("http_code")
        .or_else(|| v.get("response_code"))
        .and_then(|v| v.as_u64())
        .map(|c| c as u16);

    let num_connects = v.get("num_connects").and_then(|v| v.as_u64()).map(|c| c as u32);
    let num_redirects = v.get("num_redirects").and_then(|v| v.as_u64()).map(|c| c as u32);
    let redirect_url = v.get("redirect_url").and_then(|v| v.as_str())
        .filter(|s| !s.is_empty()).map(|s| s.to_string());
    let size_download = v.get("size_download").and_then(|v| v.as_u64());
    let size_request = v.get("size_request").and_then(|v| v.as_u64());
    let size_header = v.get("size_header").and_then(|v| v.as_u64());
    let time_namelookup = v.get("time_namelookup").and_then(|v| v.as_f64());
    let time_connect = v.get("time_connect").and_then(|v| v.as_f64());
    let time_appconnect = v.get("time_appconnect").and_then(|v| v.as_f64());
    let time_starttransfer = v.get("time_starttransfer").and_then(|v| v.as_f64());
    let time_total = v.get("time_total").and_then(|v| v.as_f64());
    let scheme = v.get("scheme").and_then(|v| v.as_str())
        .filter(|s| !s.is_empty()).map(|s| s.to_string());

    CurlWriteOut {
        http_code,
        num_connects,
        num_redirects,
        redirect_url,
        size_download,
        size_request,
        size_header,
        time_namelookup,
        time_connect,
        time_appconnect,
        time_starttransfer,
        time_total,
        scheme,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_result_fields() {
        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: "Hello".to_string(),
            stderr: "".to_string(),
            duration_ms: 100,
            http_status: Some(200),
            peak_rss_kb: None,
            cpu_user_ms: None,
            cpu_sys_ms: None,
            core_dumped: false,
            timed_out: false,
            max_fd_count: None,
            server_malformation: None,
            write_out: CurlWriteOut::default(),
            coverage_edges: vec![],
        };

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.signal, None);
        assert_eq!(result.stdout, "Hello");
        assert_eq!(result.stderr, "");
        assert_eq!(result.duration_ms, 100);
        assert_eq!(result.http_status, Some(200));
    }

    #[test]
    fn test_crashed_returns_signal() {
        let result = ExecutionResult {
            exit_code: -1,
            signal: Some(11),
            stdout: "".to_string(),
            stderr: "Segmentation fault".to_string(),
            duration_ms: 50,
            http_status: None,
            peak_rss_kb: None,
            cpu_user_ms: None,
            cpu_sys_ms: None,
            core_dumped: false,
            timed_out: false,
            max_fd_count: None,
            server_malformation: None,
            write_out: CurlWriteOut::default(),
            coverage_edges: vec![],
        };

        assert_eq!(result.crashed(), Some(11));
    }

    #[test]
    fn test_crashed_returns_none_when_no_signal() {
        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: "".to_string(),
            stderr: "".to_string(),
            duration_ms: 100,
            http_status: Some(200),
            peak_rss_kb: None,
            cpu_user_ms: None,
            cpu_sys_ms: None,
            core_dumped: false,
            timed_out: false,
            max_fd_count: None,
            server_malformation: None,
            write_out: CurlWriteOut::default(),
            coverage_edges: vec![],
        };

        assert_eq!(result.crashed(), None);
    }

    #[test]
    fn test_extract_write_out_json() {
        let stdout = "Response body\nMore content\n__CURL_JSON__\n{\"http_code\":200,\"num_connects\":1,\"num_redirects\":0,\"size_download\":528,\"size_request\":79,\"size_header\":303,\"time_namelookup\":0.01,\"time_connect\":0.02,\"time_appconnect\":0.0,\"time_starttransfer\":0.04,\"time_total\":0.05,\"scheme\":\"http\",\"redirect_url\":null}";
        let (cleaned, wo) = extract_write_out(stdout);

        assert_eq!(cleaned, "Response body\nMore content");
        assert_eq!(wo.http_code, Some(200));
        assert_eq!(wo.num_connects, Some(1));
        assert_eq!(wo.num_redirects, Some(0));
        assert_eq!(wo.size_download, Some(528));
        assert_eq!(wo.size_request, Some(79));
        assert_eq!(wo.time_total, Some(0.05));
        assert_eq!(wo.scheme, Some("http".to_string()));
        assert_eq!(wo.redirect_url, None);
    }

    #[test]
    fn test_extract_write_out_fallback_http_code() {
        // Backwards compat: plain http_code on last line
        let stdout = "Response body\n200";
        let (cleaned, wo) = extract_write_out(stdout);

        assert_eq!(cleaned, "Response body");
        assert_eq!(wo.http_code, Some(200));
        assert_eq!(wo.num_connects, None);
    }

    #[test]
    fn test_extract_write_out_empty() {
        let (cleaned, wo) = extract_write_out("");
        assert_eq!(cleaned, "");
        assert_eq!(wo.http_code, None);
    }

    #[test]
    fn test_extract_write_out_no_marker() {
        let stdout = "Response body\nNo status here";
        let (cleaned, wo) = extract_write_out(stdout);
        assert_eq!(cleaned, stdout);
        assert_eq!(wo.http_code, None);
    }

    #[test]
    fn test_parse_write_out_json_invalid() {
        let wo = parse_write_out_json("not json");
        assert_eq!(wo.http_code, None);
    }

    #[test]
    fn test_execute_curl_with_version() {
        // This test requires curl to be on PATH
        let result = execute_curl("curl", &["--version".to_string()], 5000, false, false, 5, None, None);

        match result {
            Ok(exec_result) => {
                assert_eq!(exec_result.exit_code, 0);
                assert!(exec_result.stdout.contains("curl"));
            }
            Err(e) => {
                // Skip test if curl is not available
                println!("Skipping test - curl not available: {}", e);
            }
        }
    }

    #[test]
    fn test_build_curl_command_injects_cacert_for_tls() {
        let args = build_injected_args(
            &["--verbose".to_string()],
            5000,
            true,   // is_tls
            false,  // is_blocking
            5,
            Some("/tmp/cert.pem"),
        );
        assert!(args.contains(&"--cacert".to_string()));
        assert!(args.contains(&"/tmp/cert.pem".to_string()));
    }

    #[test]
    fn test_build_curl_command_uses_blocking_timeout() {
        let args = build_injected_args(
            &["--verbose".to_string()],
            30000,
            false,
            true,   // is_blocking
            3,      // blocking_timeout_s
            None,
        );
        let max_time_idx = args.iter().position(|a| a == "--max-time").unwrap();
        assert_eq!(args[max_time_idx + 1], "3");
    }

    #[test]
    fn test_coverage_config_fields() {
        let cfg = CoverageConfig {
            source_root: "/src/curl".to_string(),
            strip_count: 5,
        };
        assert_eq!(cfg.source_root, "/src/curl");
        assert_eq!(cfg.strip_count, 5);
    }

    #[test]
    fn test_build_injected_args_no_cacert_for_non_tls() {
        let args = build_injected_args(
            &["--verbose".to_string()],
            5000,
            false,  // not TLS
            false,
            5,
            Some("/tmp/cert.pem"),
        );
        assert!(!args.contains(&"--cacert".to_string()));
    }
}
