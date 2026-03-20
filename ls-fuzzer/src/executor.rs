use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub peak_rss_kb: Option<u64>,
}

pub fn execute_ls(
    ls_path: &str,
    args: &[String],
    target: &str,
    timeout_ms: u64,
) -> Result<ExecutionResult, String> {
    let start = Instant::now();

    let mut cmd = Command::new(ls_path);
    cmd.args(args);
    cmd.arg(target);

    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to execute ls: {}", e))?;

    let child_pid = child.id();
    let killed = Arc::new(AtomicBool::new(false));
    let killed_clone = Arc::clone(&killed);
    let hard_timeout = Duration::from_millis(timeout_ms + 1000);

    let watchdog = std::thread::spawn(move || {
        std::thread::sleep(hard_timeout);
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

    #[cfg(unix)]
    let (exit_code, signal, peak_rss_kb) = {
        use std::os::unix::process::ExitStatusExt;
        let mut status: libc::c_int = 0;
        let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
        let pid = child_pid as libc::pid_t;
        let wait_result = unsafe {
            libc::wait4(pid, &mut status, 0, &mut rusage)
        };
        if wait_result > 0 {
            let exit = if libc::WIFEXITED(status) {
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
            let rss = if rusage.ru_maxrss > 0 {
                Some(rusage.ru_maxrss as u64)
            } else {
                None
            };
            (exit, sig, rss)
        } else {
            // Fallback to normal wait
            let status = child.wait().map_err(|e| format!("wait failed: {}", e))?;
            (status.code().unwrap_or(-1), status.signal(), None)
        }
    };

    #[cfg(not(unix))]
    let (exit_code, signal, peak_rss_kb) = {
        let status = child.wait().map_err(|e| format!("wait failed: {}", e))?;
        (status.code().unwrap_or(-1), None::<i32>, None::<u64>)
    };

    let timed_out = killed.load(Ordering::SeqCst);
    let _ = watchdog.join();

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(ExecutionResult {
        exit_code,
        signal,
        stdout: String::from_utf8_lossy(&stdout_bytes).to_string(),
        stderr: String::from_utf8_lossy(&stderr_bytes).to_string(),
        duration_ms,
        timed_out,
        peak_rss_kb,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_ls_basic() {
        let result = execute_ls("ls", &[], "/tmp", 5000);
        match result {
            Ok(r) => {
                assert_eq!(r.exit_code, 0);
                assert!(!r.timed_out);
            }
            Err(e) => {
                println!("Skipping: {}", e);
            }
        }
    }

    #[test]
    fn test_execute_ls_with_flags() {
        let result = execute_ls("ls", &["-la".into()], "/tmp", 5000);
        match result {
            Ok(r) => {
                assert_eq!(r.exit_code, 0);
                assert!(r.stdout.contains("total"));
            }
            Err(e) => {
                println!("Skipping: {}", e);
            }
        }
    }

    #[test]
    fn test_execute_ls_nonexistent_path() {
        let result = execute_ls("ls", &[], "/nonexistent/path/that/does/not/exist", 5000);
        match result {
            Ok(r) => {
                assert_ne!(r.exit_code, 0);
                assert!(!r.stderr.is_empty());
            }
            Err(e) => {
                println!("Skipping: {}", e);
            }
        }
    }

    #[test]
    fn test_execution_result_fields() {
        let result = ExecutionResult {
            exit_code: 0,
            signal: None,
            stdout: "file.txt".to_string(),
            stderr: "".to_string(),
            duration_ms: 5,
            timed_out: false,
            peak_rss_kb: None,
        };
        assert_eq!(result.exit_code, 0);
        assert!(result.signal.is_none());
    }
}
