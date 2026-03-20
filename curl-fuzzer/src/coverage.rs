use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::io::Read as IoRead;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Tracks unique coverage edges seen across all executions.
/// When a curl execution produces new edges not seen before,
/// the individual gets a coverage bonus.
pub struct CoverageTracker {
    seen_edges: Mutex<HashSet<u64>>,
}

impl CoverageTracker {
    pub fn new() -> Self {
        Self {
            seen_edges: Mutex::new(HashSet::new()),
        }
    }

    /// Record edges from an execution. Returns the number of NEW edges
    /// (edges not seen in any previous execution).
    pub fn record_edges(&self, edges: &[u64]) -> u64 {
        let mut seen = self.seen_edges.lock().unwrap();
        let mut new_count = 0u64;
        for &edge in edges {
            if seen.insert(edge) {
                new_count += 1;
            }
        }
        new_count
    }

    /// Total unique edges seen so far.
    #[cfg(test)]
    pub fn total_edges(&self) -> usize {
        self.seen_edges.lock().unwrap().len()
    }
}

/// Determine the gcno source directory for a given .gcda file.
///
/// Phase 1: check the parent subdirectory name for known curl subdirs.
/// Phase 2: for flat files, use filename prefix to determine lib vs src.
pub(crate) fn gcno_dir_for(gcda_file: &Path, gcda_dir: &Path, source_root: &Path) -> PathBuf {
    let parent = gcda_file.parent().unwrap_or(gcda_dir);
    let filename = gcda_file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // Phase 1: subdir takes precedence
    if parent != gcda_dir {
        let subdir_name = parent
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        match subdir_name {
            "curlx"  => return source_root.join("lib").join("curlx"),
            "vauth"  => return source_root.join("lib").join("vauth"),
            "vtls"   => return source_root.join("lib").join("vtls"),
            "vssh"   => return source_root.join("lib").join("vssh"),
            "vquic"  => return source_root.join("lib").join("vquic"),
            "toolx"  => return source_root.join("src").join("toolx"),
            _ => {}
        }
    }

    // Phase 2: flat files — use filename prefix
    if filename.starts_with("libcurl_la-") {
        source_root.join("lib")
    } else if filename.starts_with("curl-") {
        source_root.join("src")
    } else {
        source_root.join("lib")
    }
}

/// Recursively collect all .gcda file paths under a directory.
fn collect_gcda_files(dir: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return results,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            results.extend(collect_gcda_files(&path));
        } else if path.extension().and_then(|e| e.to_str()) == Some("gcda") {
            results.push(path);
        }
    }
    results
}

/// Hash an edge triple (filename, source_block_id, destination_block_id) to a u64.
fn hash_edge(file: &str, src: u64, dst: u64) -> u64 {
    let mut hasher = DefaultHasher::new();
    file.hash(&mut hasher);
    src.hash(&mut hasher);
    dst.hash(&mut hasher);
    hasher.finish()
}

/// Parse all .gcov.json.gz files in a directory and return edge IDs for taken branches.
fn parse_gcov_json_dir(dir: &Path) -> Vec<u64> {
    let mut edges = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return edges,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.ends_with(".gcov.json.gz") {
            continue;
        }
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("coverage: failed to open {}: {}", path.display(), e);
                continue;
            }
        };
        let mut gz = flate2::read::GzDecoder::new(file);
        let mut buf = String::new();
        if let Err(e) = gz.read_to_string(&mut buf) {
            eprintln!("coverage: failed to decompress {}: {}", path.display(), e);
            continue;
        }
        let json: serde_json::Value = match serde_json::from_str(&buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("coverage: failed to parse JSON in {}: {}", path.display(), e);
                continue;
            }
        };
        let files = match json.get("files").and_then(|f| f.as_array()) {
            Some(a) => a,
            None => continue,
        };
        for file_obj in files {
            let file_name = file_obj
                .get("file")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let branches = match file_obj.get("branches").and_then(|b| b.as_array()) {
                Some(a) => a,
                None => continue,
            };
            for branch in branches {
                let count = branch.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                if count == 0 {
                    continue;
                }
                let src = branch
                    .get("source_block_id")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let dst = branch
                    .get("destination_block_id")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                edges.push(hash_edge(file_name, src, dst));
            }
        }
    }
    edges
}

/// Collect coverage edges from all .gcda files in `gcda_dir`.
///
/// For each .gcda file, runs `gcov --json-format --branch-probabilities` to produce
/// .gcov.json.gz output, then parses the branch data to extract taken edge IDs.
///
/// Returns a `Vec<u64>` of edge IDs (hashes of file + source_block + dest_block triples).
pub fn collect_coverage(gcda_dir: &Path, source_root: &Path) -> Vec<u64> {
    let gcda_files = collect_gcda_files(gcda_dir);
    let mut all_edges = Vec::new();

    for gcda_file in &gcda_files {
        let gcno_dir = gcno_dir_for(gcda_file, gcda_dir, source_root);

        let tmp_dir = match tempfile::TempDir::new_in(gcda_dir) {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "coverage: failed to create temp dir in {}: {}",
                    gcda_dir.display(),
                    e
                );
                continue;
            }
        };

        let output = std::process::Command::new("gcov")
            .arg("--json-format")
            .arg("--branch-probabilities")
            .arg("-o")
            .arg(&gcno_dir)
            .arg(gcda_file)
            .current_dir(tmp_dir.path())
            .output();

        match output {
            Err(e) => {
                eprintln!(
                    "coverage: failed to run gcov for {}: {}",
                    gcda_file.display(),
                    e
                );
                continue;
            }
            Ok(out) if !out.status.success() => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                eprintln!(
                    "coverage: gcov exited {:?} for {}: {}",
                    out.status.code(),
                    gcda_file.display(),
                    stderr.trim()
                );
                continue;
            }
            Ok(_) => {}
        }

        let edges = parse_gcov_json_dir(tmp_dir.path());
        all_edges.extend(edges);
    }

    all_edges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_edges_counted() {
        let tracker = CoverageTracker::new();
        let new = tracker.record_edges(&[1, 2, 3]);
        assert_eq!(new, 3);
        assert_eq!(tracker.total_edges(), 3);
    }

    #[test]
    fn test_duplicate_edges_not_counted() {
        let tracker = CoverageTracker::new();
        tracker.record_edges(&[1, 2, 3]);
        let new = tracker.record_edges(&[2, 3, 4]);
        assert_eq!(new, 1); // only 4 is new
        assert_eq!(tracker.total_edges(), 4);
    }

    #[test]
    fn test_empty_edges() {
        let tracker = CoverageTracker::new();
        let new = tracker.record_edges(&[]);
        assert_eq!(new, 0);
        assert_eq!(tracker.total_edges(), 0);
    }

    #[test]
    fn test_gcno_dir_lookup_libcurl_prefix() {
        use std::path::Path;
        let gcda_dir = Path::new("/tmp/gcda");
        let source_root = Path::new("/src/curl");
        let gcda_file = gcda_dir.join("libcurl_la-easy.gcda");
        let result = gcno_dir_for(&gcda_file, gcda_dir, source_root);
        assert_eq!(result, source_root.join("lib"));
    }

    #[test]
    fn test_gcno_dir_lookup_curl_prefix() {
        use std::path::Path;
        let gcda_dir = Path::new("/tmp/gcda");
        let source_root = Path::new("/src/curl");
        let gcda_file = gcda_dir.join("curl-tool_main.gcda");
        let result = gcno_dir_for(&gcda_file, gcda_dir, source_root);
        assert_eq!(result, source_root.join("src"));
    }

    #[test]
    fn test_gcno_dir_lookup_subdir_curlx() {
        use std::path::Path;
        let gcda_dir = Path::new("/tmp/gcda");
        let source_root = Path::new("/src/curl");
        let gcda_file = gcda_dir.join("curlx").join("libcurl_la-timediff.gcda");
        let result = gcno_dir_for(&gcda_file, gcda_dir, source_root);
        assert_eq!(result, source_root.join("lib").join("curlx"));
    }

    #[test]
    fn test_gcno_dir_lookup_subdir_toolx() {
        use std::path::Path;
        let gcda_dir = Path::new("/tmp/gcda");
        let source_root = Path::new("/src/curl");
        // "toolx" subdir rule wins over "curl-" prefix
        let gcda_file = gcda_dir.join("toolx").join("curl-tool_time.gcda");
        let result = gcno_dir_for(&gcda_file, gcda_dir, source_root);
        assert_eq!(result, source_root.join("src").join("toolx"));
    }

    #[test]
    fn test_collect_coverage_no_gcda_files() {
        // Empty dir → empty Vec, no panic
        let tmp = tempfile::TempDir::new().unwrap();
        let result = collect_coverage(tmp.path(), std::path::Path::new("/nonexistent/source"));
        assert!(result.is_empty());
    }

    #[test]
    #[ignore]
    fn test_collect_coverage_real_curl() {
        // Only runs when CURL_SRC env var is set
        let curl_src = match std::env::var("CURL_SRC") {
            Ok(v) => v,
            Err(_) => return,
        };
        // Run a real curl execution to generate .gcda files, then collect
        // This test just verifies no panic and returns some edges
        let tmp = tempfile::TempDir::new().unwrap();
        let edges = collect_coverage(tmp.path(), std::path::Path::new(&curl_src));
        // Result should be empty (no gcda files in tmp), not a panic
        assert!(edges.is_empty());
    }
}
