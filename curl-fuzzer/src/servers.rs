use crate::protocol::{ServerSpawnEntry, Transport};
use anyhow::Result;
use std::collections::HashMap;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ServerConfig {
    pub script: String,
    pub port: u16,
    pub extra_args: Vec<String>,
}

impl ServerConfig {
    #[allow(dead_code)]
    pub fn to_command_args(&self) -> Vec<String> {
        let mut args = vec!["--port".to_string(), self.port.to_string()];
        args.extend(self.extra_args.iter().cloned());
        args
    }
}

pub struct ServerManager {
    servers: HashMap<String, Child>,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub fixtures_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl ServerManager {
    pub fn new() -> Self {
        let state_dir = PathBuf::from("/tmp/curl-fuzz-server-state");
        let _ = std::fs::create_dir_all(&state_dir);
        Self {
            servers: HashMap::new(),
            cert_path: None,
            key_path: None,
            fixtures_dir: PathBuf::from("/tmp/curl-fuzz-fixtures"),
            state_dir,
        }
    }

    /// Generate shared TLS certificates using tls_wrapper.py
    pub fn generate_certs(&mut self) -> Result<()> {
        let cert_dir = "/tmp/curl-fuzz-certs";
        let output = Command::new("python3")
            .arg("-c")
            .arg(format!(
                "import sys; sys.path.insert(0,'test-servers'); from tls_wrapper import generate_cert; c,k = generate_cert('{}'); print(c); print(k)",
                cert_dir
            ))
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to generate certs: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.trim().lines().collect();
        if lines.len() >= 2 {
            self.cert_path = Some(PathBuf::from(lines[0]));
            self.key_path = Some(PathBuf::from(lines[1]));
        }
        Ok(())
    }

    /// Create file:// test fixtures in /tmp/curl-fuzz-fixtures/
    pub fn create_fixtures(&self) -> Result<()> {
        use std::fs;
        fs::create_dir_all(&self.fixtures_dir)?;
        fs::write(self.fixtures_dir.join("empty.txt"), "")?;
        fs::write(self.fixtures_dir.join("small.txt"), "Test content for curl fuzzing.\n")?;
        // Large binary: 10MB of repeating pattern
        let large: Vec<u8> = (0..10_000_000).map(|i| (i % 256) as u8).collect();
        fs::write(self.fixtures_dir.join("large.bin"), &large)?;
        fs::write(self.fixtures_dir.join("special chars!.txt"), "Special filename test.\n")?;
        // Symlink
        let symlink_path = self.fixtures_dir.join("symlink.txt");
        if !symlink_path.exists() {
            let _ = std::os::unix::fs::symlink(
                self.fixtures_dir.join("small.txt"),
                symlink_path,
            );
        }
        Ok(())
    }

    /// Start servers from a protocol-driven spawn list (from ProtocolRegistry::server_spawn_list)
    pub fn start_protocols(&mut self, spawn_list: &[ServerSpawnEntry], server_mode: &str) -> Result<Vec<u16>> {
        let mut failed_ports = Vec::new();

        for entry in spawn_list {
            let mut cmd = Command::new("python3");
            cmd.arg(&entry.script);
            cmd.arg("--port").arg(entry.port.to_string());
            cmd.arg("--mode").arg(server_mode);
            cmd.arg("--state-dir").arg(&self.state_dir);

            if entry.tls {
                if let (Some(cert), Some(key)) = (&self.cert_path, &self.key_path) {
                    cmd.arg("--tls");
                    cmd.arg("--certfile").arg(cert);
                    cmd.arg("--keyfile").arg(key);
                }
            }

            let key = format!("{}:{}", entry.script, entry.port);
            match cmd.spawn() {
                Ok(child) => {
                    self.servers.insert(key, child);
                }
                Err(e) => {
                    eprintln!("  Failed to start {} on port {}: {}", entry.script, entry.port, e);
                    failed_ports.push(entry.port);
                }
            }
        }

        // Wait for servers to start
        thread::sleep(Duration::from_secs(2));

        // Health check each server
        for entry in spawn_list {
            if failed_ports.contains(&entry.port) {
                continue;
            }
            let ok = match entry.transport {
                Transport::Tcp => health_check_tcp("localhost", entry.port, 3),
                Transport::Udp => health_check_udp(entry.port),
            };
            if !ok {
                eprintln!("  Health check failed for {} on port {}", entry.script, entry.port);
                failed_ports.push(entry.port);
            }
        }

        if !spawn_list.is_empty() && failed_ports.len() == spawn_list.len() {
            return Err(anyhow::anyhow!("All servers failed to start"));
        }

        Ok(failed_ports)
    }

    /// Legacy start method for backwards compatibility (used by Servers subcommand)
    #[allow(dead_code)]
    pub fn start(&mut self, configs: &[ServerConfig]) -> Result<Vec<u16>> {
        let mut failed_ports = Vec::new();

        for config in configs {
            let args = config.to_command_args();
            match Command::new("python3")
                .arg(&config.script)
                .args(&args)
                .spawn()
            {
                Ok(child) => {
                    let key = format!("{}:{}", config.script, config.port);
                    self.servers.insert(key, child);
                }
                Err(e) => {
                    eprintln!("  Failed to start {}: {}", config.script, e);
                    failed_ports.push(config.port);
                }
            }
        }

        // Wait for servers to start
        thread::sleep(Duration::from_secs(2));

        // Health check each server that was spawned
        for config in configs {
            if failed_ports.contains(&config.port) {
                continue;
            }
            if !health_check_tcp("localhost", config.port, 3) {
                eprintln!("  Health check failed for {} on port {}", config.script, config.port);
                failed_ports.push(config.port);
            }
        }

        if failed_ports.len() == configs.len() {
            return Err(anyhow::anyhow!("All servers failed to start"));
        }

        Ok(failed_ports)
    }

    pub fn stop(&mut self) {
        for (_, child) in &mut self.servers {
            let _ = child.kill();
        }
        self.servers.clear();
    }
}

impl Drop for ServerManager {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn health_check_tcp(host: &str, port: u16, retries: usize) -> bool {
    use std::net::ToSocketAddrs;
    for _ in 0..retries {
        let addr = format!("{}:{}", host, port);
        if let Ok(addrs) = addr.to_socket_addrs() {
            for sock_addr in addrs {
                if TcpStream::connect_timeout(&sock_addr, Duration::from_secs(1)).is_ok() {
                    return true;
                }
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
    false
}

pub fn health_check_udp(port: u16) -> bool {
    use std::net::UdpSocket;
    // Send a minimal TFTP RRQ: opcode=1, filename="test.txt", mode="octet"
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
    // TFTP RRQ packet
    let mut packet = vec![0u8, 1]; // opcode 1 = RRQ
    packet.extend_from_slice(b"test.txt\0octet\0");

    if sock.send_to(&packet, format!("127.0.0.1:{}", port)).is_err() {
        return false;
    }

    let mut buf = [0u8; 516];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) if n > 0 => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_command_args_format() {
        let config = ServerConfig {
            script: "server.py".to_string(),
            port: 8080,
            extra_args: vec!["--verbose".to_string(), "--debug".to_string()],
        };

        let args = config.to_command_args();

        assert_eq!(args[0], "--port");
        assert_eq!(args[1], "8080");
        assert_eq!(args[2], "--verbose");
        assert_eq!(args[3], "--debug");
    }

    #[test]
    fn test_to_command_args_no_extra_args() {
        let config = ServerConfig {
            script: "server.py".to_string(),
            port: 9090,
            extra_args: vec![],
        };

        let args = config.to_command_args();

        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "--port");
        assert_eq!(args[1], "9090");
    }

    #[test]
    fn test_health_check_on_closed_port() {
        let result = health_check_tcp("localhost", 65534, 1);
        assert_eq!(result, false);
    }

    #[test]
    fn test_server_manager_new() {
        let manager = ServerManager::new();
        assert_eq!(manager.servers.len(), 0);
        assert!(manager.cert_path.is_none());
        assert!(manager.key_path.is_none());
        assert_eq!(manager.fixtures_dir, PathBuf::from("/tmp/curl-fuzz-fixtures"));
    }

    #[test]
    fn test_server_manager_stores_cert_path() {
        let manager = ServerManager::new();
        assert!(manager.cert_path.is_none());
    }

    #[test]
    fn test_create_fixtures() {
        let manager = ServerManager::new();
        // Use a unique temp dir to avoid conflicts
        let result = manager.create_fixtures();
        assert!(result.is_ok());
        assert!(manager.fixtures_dir.join("empty.txt").exists());
        assert!(manager.fixtures_dir.join("small.txt").exists());
        assert!(manager.fixtures_dir.join("large.bin").exists());
        assert!(manager.fixtures_dir.join("special chars!.txt").exists());
    }
}
