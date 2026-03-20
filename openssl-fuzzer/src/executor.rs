use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    #[allow(dead_code)]
    pub timed_out: bool,
    pub peak_rss_kb: Option<u64>,
    pub cpu_user_ms: Option<u64>,
    pub cpu_sys_ms: Option<u64>,
    pub max_fd_count: Option<u32>,
}

/// Execute openssl s_client (legacy wrapper).
pub fn execute_openssl(
    openssl_path: &str,
    connect: &str,
    args: &[String],
    timeout_ms: u64,
) -> Result<ExecutionResult, String> {
    let fixed_args: Vec<String> = vec![
        "-connect".to_string(), connect.to_string(),
        "-no-interactive".to_string(),
    ];
    execute_openssl_cmd(openssl_path, "s_client", &fixed_args, args, Some("Q\n"), timeout_ms)
}

/// Generic openssl subcommand executor.
pub fn execute_openssl_cmd(
    openssl_path: &str,
    subcommand: &str,
    fixed_args: &[String],
    args: &[String],
    stdin_input: Option<&str>,
    timeout_ms: u64,
) -> Result<ExecutionResult, String> {
    let start = Instant::now();

    let mut cmd = Command::new(openssl_path);
    cmd.arg(subcommand);
    cmd.args(fixed_args);
    cmd.args(args);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn()
        .map_err(|e| format!("Failed to execute openssl {}: {}", subcommand, e))?;

    // Write stdin if needed (e.g. "Q\n" for s_client)
    if let Some(input) = stdin_input {
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(input.as_bytes());
            let _ = stdin.flush();
        }
    }
    // Drop stdin to close the pipe
    drop(child.stdin.take());

    let child_pid = child.id();
    let killed = Arc::new(AtomicBool::new(false));
    let killed_clone = Arc::clone(&killed);
    let max_fd = Arc::new(AtomicU32::new(0));
    let max_fd_clone = Arc::clone(&max_fd);
    let hard_timeout = Duration::from_millis(timeout_ms + 1000);

    let watchdog = std::thread::spawn(move || {
        let start = Instant::now();
        let proc_fd_path = format!("/proc/{}/fd", child_pid);
        while start.elapsed() < hard_timeout {
            // Sample FD count
            if let Ok(entries) = std::fs::read_dir(&proc_fd_path) {
                let count = entries.count() as u32;
                max_fd_clone.fetch_max(count, Ordering::Relaxed);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        #[cfg(unix)]
        unsafe {
            libc::kill(child_pid as libc::pid_t, libc::SIGKILL);
        }
        killed_clone.store(true, Ordering::SeqCst);
    });

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
    let (exit_code, signal, peak_rss_kb, cpu_user_ms, cpu_sys_ms) = {
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
            (output_status.code().unwrap_or(-1), output_status.signal(), None, None, None)
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
            // ru_maxrss is in KB on Linux
            let rss = rusage.ru_maxrss as u64;
            // CPU time from rusage (seconds + microseconds -> milliseconds)
            let cpu_user = (rusage.ru_utime.tv_sec as u64) * 1000
                + (rusage.ru_utime.tv_usec as u64) / 1000;
            let cpu_sys = (rusage.ru_stime.tv_sec as u64) * 1000
                + (rusage.ru_stime.tv_usec as u64) / 1000;
            (exit_code, sig, Some(rss), Some(cpu_user), Some(cpu_sys))
        }
    };

    #[cfg(not(unix))]
    let (exit_code, signal, peak_rss_kb, cpu_user_ms, cpu_sys_ms) = {
        let status = child.wait().map_err(|e| format!("wait failed: {}", e))?;
        (status.code().unwrap_or(-1), None::<i32>, None, None, None)
    };

    let timed_out = killed.load(Ordering::SeqCst);
    let _ = watchdog.join();

    let max_fd_count = {
        let v = max_fd.load(Ordering::Relaxed);
        if v > 0 { Some(v) } else { None }
    };

    Ok(ExecutionResult {
        exit_code,
        signal,
        stdout: String::from_utf8_lossy(&stdout_bytes).to_string(),
        stderr: String::from_utf8_lossy(&stderr_bytes).to_string(),
        duration_ms: start.elapsed().as_millis() as u64,
        timed_out,
        peak_rss_kb,
        cpu_user_ms,
        cpu_sys_ms,
        max_fd_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_result_fields() {
        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: "certificate chain".to_string(),
            stderr: "".to_string(),
            duration_ms: 50,
            timed_out: false,
            peak_rss_kb: Some(12000),
            cpu_user_ms: Some(10),
            cpu_sys_ms: Some(5),
            max_fd_count: Some(8),
        };
        assert_eq!(result.exit_code, 0);
        assert!(result.signal.is_none());
        assert!(!result.timed_out);
        assert_eq!(result.peak_rss_kb, Some(12000));
        assert_eq!(result.cpu_user_ms, Some(10));
        assert_eq!(result.max_fd_count, Some(8));
    }

    #[test]
    fn test_execution_result_with_signal() {
        let result = ExecutionResult {
            exit_code: -1,
            signal: Some(11),
            stdout: "".to_string(),
            stderr: "Segmentation fault".to_string(),
            duration_ms: 5,
            timed_out: false,
            peak_rss_kb: None,
            cpu_user_ms: None,
            cpu_sys_ms: None,
            max_fd_count: None,
        };
        assert_eq!(result.signal, Some(11));
    }
}
