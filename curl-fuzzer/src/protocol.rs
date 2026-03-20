use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct ProtocolDef {
    pub name: String,
    pub scheme: String,
    pub default_port: u16,
    pub tls_variant_of: Option<String>,
    pub server_script: Option<String>,
    pub virtual_of: Option<String>,
    pub flag_affinity: Vec<String>,
    pub transport: Transport,
    pub blocking_protocol: bool,
    pub url_path: String,
}

#[derive(Debug, Clone)]
pub struct ServerSpawnEntry {
    pub script: String,
    pub port: u16,
    pub tls: bool,
    pub transport: Transport,
}

pub struct ProtocolRegistry {
    pub protocols: HashMap<String, ProtocolDef>,
}

impl ProtocolRegistry {
    pub fn get(&self, name: &str) -> Option<&ProtocolDef> {
        self.protocols.get(name)
    }

    pub fn url_for(&self, name: &str, port: u16) -> String {
        if name == "file" {
            return "file:///tmp/curl-fuzz-fixtures/small.txt".to_string();
        }
        let proto = self.get(name).expect("unknown protocol");
        format!("{}localhost:{}{}", proto.scheme, port, proto.url_path)
    }

    pub fn is_tls_protocol(&self, name: &str) -> bool {
        self.get(name)
            .map(|p| p.tls_variant_of.is_some())
            .unwrap_or(false)
    }

    fn resolve_spawn(&self, proto: &ProtocolDef, name: &str, port_overrides: &HashMap<String, u16>) -> (Option<String>, u16, bool) {
        if let Some(ref parent_name) = proto.virtual_of {
            let parent = self.get(parent_name).unwrap();
            if let Some(ref tls_of) = parent.tls_variant_of {
                let grandparent = self.get(tls_of).unwrap();
                let port = port_overrides.get(name).copied()
                    .unwrap_or(proto.default_port);
                return (grandparent.server_script.clone(), port, true);
            }
            let port = port_overrides.get(parent_name).copied()
                .unwrap_or(parent.default_port);
            return (parent.server_script.clone(), port, false);
        }
        if let Some(ref tls_of) = proto.tls_variant_of {
            let parent = self.get(tls_of).unwrap();
            let port = port_overrides.get(name).copied()
                .unwrap_or(proto.default_port);
            return (parent.server_script.clone(), port, true);
        }
        let port = port_overrides.get(name).copied()
            .unwrap_or(proto.default_port);
        (proto.server_script.clone(), port, false)
    }

    pub fn server_spawn_list(&self, enabled: &[String], port_overrides: &HashMap<String, u16>) -> Vec<ServerSpawnEntry> {
        let mut seen: HashMap<(String, u16), ServerSpawnEntry> = HashMap::new();

        for name in enabled {
            let proto = match self.get(name) {
                Some(p) => p,
                None => continue,
            };

            let (script, port, is_tls) = self.resolve_spawn(proto, name, port_overrides);

            if let Some(script) = script {
                let key = (script.clone(), port);
                seen.entry(key).or_insert(ServerSpawnEntry {
                    script,
                    port,
                    tls: is_tls,
                    transport: proto.transport.clone(),
                });
            }
        }

        seen.into_values().collect()
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        let mut protocols = HashMap::new();

        let entries: Vec<ProtocolDef> = vec![
            ProtocolDef { name: "http".into(), scheme: "http://".into(), default_port: 8080, tls_variant_of: None, server_script: Some("test-servers/http_server.py".into()), virtual_of: None, flag_affinity: vec![], transport: Transport::Tcp, blocking_protocol: false, url_path: "/".into() },
            ProtocolDef { name: "https".into(), scheme: "https://".into(), default_port: 8443, tls_variant_of: Some("http".into()), server_script: None, virtual_of: None, flag_affinity: vec![], transport: Transport::Tcp, blocking_protocol: false, url_path: "/".into() },
            ProtocolDef { name: "ftp".into(), scheme: "ftp://".into(), default_port: 2121, tls_variant_of: None, server_script: Some("test-servers/ftp_server.py".into()), virtual_of: None, flag_affinity: vec!["--ftp-pasv".into(), "--ftp-port".into(), "--ftp-ssl".into(), "--ftp-ssl-reqd".into(), "--ftp-account".into(), "--ftp-method".into(), "--ftp-skip-pasv-ip".into(), "--ftp-ssl-ccc".into(), "--ftp-ssl-ccc-mode".into(), "--ftp-create-dirs".into(), "--ftp-alternative-to-user".into()], transport: Transport::Tcp, blocking_protocol: false, url_path: "/test.txt".into() },
            ProtocolDef { name: "ftps".into(), scheme: "ftps://".into(), default_port: 9921, tls_variant_of: Some("ftp".into()), server_script: None, virtual_of: None, flag_affinity: vec![], transport: Transport::Tcp, blocking_protocol: false, url_path: "/test.txt".into() },
            ProtocolDef { name: "smtp".into(), scheme: "smtp://".into(), default_port: 2525, tls_variant_of: None, server_script: Some("test-servers/smtp_server.py".into()), virtual_of: None, flag_affinity: vec!["--mail-from".into(), "--mail-rcpt".into(), "--mail-auth".into(), "--mail-rcpt-allowfails".into(), "--sasl-authzid".into(), "--sasl-ir".into(), "--login-options".into()], transport: Transport::Tcp, blocking_protocol: false, url_path: "/user@example.com".into() },
            ProtocolDef { name: "smtps".into(), scheme: "smtps://".into(), default_port: 5587, tls_variant_of: Some("smtp".into()), server_script: None, virtual_of: None, flag_affinity: vec![], transport: Transport::Tcp, blocking_protocol: false, url_path: "/user@example.com".into() },
            ProtocolDef { name: "imap".into(), scheme: "imap://".into(), default_port: 1143, tls_variant_of: None, server_script: Some("test-servers/imap_server.py".into()), virtual_of: None, flag_affinity: vec!["--login-options".into(), "--sasl-authzid".into(), "--sasl-ir".into()], transport: Transport::Tcp, blocking_protocol: false, url_path: "/INBOX".into() },
            ProtocolDef { name: "imaps".into(), scheme: "imaps://".into(), default_port: 9933, tls_variant_of: Some("imap".into()), server_script: None, virtual_of: None, flag_affinity: vec![], transport: Transport::Tcp, blocking_protocol: false, url_path: "/INBOX".into() },
            ProtocolDef { name: "pop3".into(), scheme: "pop3://".into(), default_port: 1110, tls_variant_of: None, server_script: Some("test-servers/pop3_server.py".into()), virtual_of: None, flag_affinity: vec!["--login-options".into(), "--sasl-authzid".into(), "--sasl-ir".into()], transport: Transport::Tcp, blocking_protocol: false, url_path: "/1".into() },
            ProtocolDef { name: "pop3s".into(), scheme: "pop3s://".into(), default_port: 9955, tls_variant_of: Some("pop3".into()), server_script: None, virtual_of: None, flag_affinity: vec![], transport: Transport::Tcp, blocking_protocol: false, url_path: "/1".into() },
            ProtocolDef { name: "gopher".into(), scheme: "gopher://".into(), default_port: 7070, tls_variant_of: None, server_script: Some("test-servers/gopher_server.py".into()), virtual_of: None, flag_affinity: vec![], transport: Transport::Tcp, blocking_protocol: false, url_path: "/1".into() },
            ProtocolDef { name: "gophers".into(), scheme: "gophers://".into(), default_port: 7071, tls_variant_of: Some("gopher".into()), server_script: None, virtual_of: None, flag_affinity: vec![], transport: Transport::Tcp, blocking_protocol: false, url_path: "/1".into() },
            ProtocolDef { name: "dict".into(), scheme: "dict://".into(), default_port: 2628, tls_variant_of: None, server_script: Some("test-servers/dict_server.py".into()), virtual_of: None, flag_affinity: vec![], transport: Transport::Tcp, blocking_protocol: false, url_path: "/d:test:*".into() },
            ProtocolDef { name: "mqtt".into(), scheme: "mqtt://".into(), default_port: 1883, tls_variant_of: None, server_script: Some("test-servers/mqtt_server.py".into()), virtual_of: None, flag_affinity: vec![], transport: Transport::Tcp, blocking_protocol: true, url_path: "/topic".into() },
            ProtocolDef { name: "mqtts".into(), scheme: "mqtts://".into(), default_port: 8883, tls_variant_of: Some("mqtt".into()), server_script: None, virtual_of: None, flag_affinity: vec![], transport: Transport::Tcp, blocking_protocol: true, url_path: "/topic".into() },
            ProtocolDef { name: "tftp".into(), scheme: "tftp://".into(), default_port: 6969, tls_variant_of: None, server_script: Some("test-servers/tftp_server.py".into()), virtual_of: None, flag_affinity: vec![], transport: Transport::Udp, blocking_protocol: false, url_path: "/test.txt".into() },
            ProtocolDef { name: "telnet".into(), scheme: "telnet://".into(), default_port: 2323, tls_variant_of: None, server_script: Some("test-servers/telnet_server.py".into()), virtual_of: None, flag_affinity: vec![], transport: Transport::Tcp, blocking_protocol: true, url_path: "".into() },
            ProtocolDef { name: "ws".into(), scheme: "ws://".into(), default_port: 8080, tls_variant_of: None, server_script: Some("test-servers/http_server.py".into()), virtual_of: Some("http".into()), flag_affinity: vec!["--no-buffer".into()], transport: Transport::Tcp, blocking_protocol: false, url_path: "/ws".into() },
            ProtocolDef { name: "wss".into(), scheme: "wss://".into(), default_port: 8443, tls_variant_of: None, server_script: Some("test-servers/http_server.py".into()), virtual_of: Some("https".into()), flag_affinity: vec!["--no-buffer".into()], transport: Transport::Tcp, blocking_protocol: false, url_path: "/ws".into() },
            ProtocolDef { name: "file".into(), scheme: "file://".into(), default_port: 0, tls_variant_of: None, server_script: None, virtual_of: None, flag_affinity: vec![], transport: Transport::Tcp, blocking_protocol: false, url_path: "".into() },
        ];

        for entry in entries {
            protocols.insert(entry.name.clone(), entry);
        }

        Self { protocols }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_registry_has_20_protocols() {
        let registry = ProtocolRegistry::default();
        assert_eq!(registry.protocols.len(), 20);
    }

    #[test]
    fn test_lookup_http() {
        let registry = ProtocolRegistry::default();
        let http = registry.get("http").unwrap();
        assert_eq!(http.scheme, "http://");
        assert_eq!(http.default_port, 8080);
        assert!(http.server_script.is_some());
        assert!(http.virtual_of.is_none());
        assert!(!http.blocking_protocol);
    }

    #[test]
    fn test_lookup_ws_is_virtual() {
        let registry = ProtocolRegistry::default();
        let ws = registry.get("ws").unwrap();
        assert_eq!(ws.virtual_of.as_deref(), Some("http"));
        assert_eq!(ws.default_port, 8080);
    }

    #[test]
    fn test_lookup_file_has_no_server() {
        let registry = ProtocolRegistry::default();
        let file = registry.get("file").unwrap();
        assert!(file.server_script.is_none());
    }

    #[test]
    fn test_mqtt_is_blocking() {
        let registry = ProtocolRegistry::default();
        assert!(registry.get("mqtt").unwrap().blocking_protocol);
        assert!(registry.get("telnet").unwrap().blocking_protocol);
        assert!(!registry.get("http").unwrap().blocking_protocol);
    }

    #[test]
    fn test_tls_variants() {
        let registry = ProtocolRegistry::default();
        let ftps = registry.get("ftps").unwrap();
        assert_eq!(ftps.tls_variant_of.as_deref(), Some("ftp"));
        assert_eq!(ftps.default_port, 9921);
    }

    #[test]
    fn test_url_for_protocol() {
        let registry = ProtocolRegistry::default();
        assert_eq!(registry.url_for("http", 8080), "http://localhost:8080/");
        assert_eq!(registry.url_for("ftp", 2121), "ftp://localhost:2121/test.txt");
        assert_eq!(registry.url_for("dict", 2628), "dict://localhost:2628/d:test:*");
    }

    #[test]
    fn test_transport_types() {
        let registry = ProtocolRegistry::default();
        assert_eq!(registry.get("tftp").unwrap().transport, Transport::Udp);
        assert_eq!(registry.get("http").unwrap().transport, Transport::Tcp);
    }

    #[test]
    fn test_spawn_dedup_http_ws() {
        let registry = ProtocolRegistry::default();
        let entries = registry.server_spawn_list(
            &["http".into(), "ws".into()],
            &HashMap::new(),
        );
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_spawn_ftp_ftps_separate() {
        let registry = ProtocolRegistry::default();
        let entries = registry.server_spawn_list(
            &["ftp".into(), "ftps".into()],
            &HashMap::new(),
        );
        assert_eq!(entries.len(), 2);
        let tls_entry = entries.iter().find(|e| e.tls).unwrap();
        assert_eq!(tls_entry.port, 9921);
    }

    #[test]
    fn test_wss_spawn_resolves_to_http_server() {
        let registry = ProtocolRegistry::default();
        let entries = registry.server_spawn_list(
            &["wss".into()],
            &HashMap::new(),
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].script, "test-servers/http_server.py");
        assert!(entries[0].tls);
        assert_eq!(entries[0].port, 8443);
    }

    #[test]
    fn test_is_tls_protocol() {
        let registry = ProtocolRegistry::default();
        assert!(registry.is_tls_protocol("https"));
        assert!(registry.is_tls_protocol("ftps"));
        assert!(!registry.is_tls_protocol("http"));
        assert!(!registry.is_tls_protocol("ftp"));
    }
}
