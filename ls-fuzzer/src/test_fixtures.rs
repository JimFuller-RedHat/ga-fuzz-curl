use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use tempfile::TempDir;

pub struct TestFixtures {
    pub dir: TempDir,
}

impl TestFixtures {
    pub fn create() -> Result<Self, String> {
        let dir = TempDir::new().map_err(|e| format!("Failed to create temp dir: {}", e))?;
        let base = dir.path();

        // Regular files
        fs::write(base.join("normal.txt"), "hello world").map_err(|e| e.to_string())?;
        fs::write(base.join("empty.txt"), "").map_err(|e| e.to_string())?;
        fs::write(base.join(".hidden"), "hidden file").map_err(|e| e.to_string())?;
        fs::write(base.join(".hidden_dir_file"), "another hidden").map_err(|e| e.to_string())?;

        // Large file
        let large_data = vec![b'X'; 1_000_000];
        fs::write(base.join("large.bin"), &large_data).map_err(|e| e.to_string())?;

        // Files with special characters
        fs::write(base.join("spaces in name.txt"), "spaces").map_err(|e| e.to_string())?;
        fs::write(base.join("tab\there.txt"), "tab").map_err(|e| e.to_string())?;
        fs::write(base.join("newline\nname.txt"), "newline").unwrap_or(()); // may fail on some FS

        // Subdirectories
        let sub = base.join("subdir");
        fs::create_dir(&sub).map_err(|e| e.to_string())?;
        fs::write(sub.join("nested.txt"), "nested file").map_err(|e| e.to_string())?;

        let deep = sub.join("deep").join("deeper");
        fs::create_dir_all(&deep).map_err(|e| e.to_string())?;
        fs::write(deep.join("bottom.txt"), "deep file").map_err(|e| e.to_string())?;

        // Empty directory
        fs::create_dir(base.join("empty_dir")).map_err(|e| e.to_string())?;

        // Symlinks
        let _ = symlink(base.join("normal.txt"), base.join("link_to_normal"));
        let _ = symlink(base.join("subdir"), base.join("link_to_subdir"));
        // Broken symlink
        let _ = symlink("/nonexistent/target", base.join("broken_link"));
        // Circular symlink
        let _ = symlink(base.join("circular_b"), base.join("circular_a"));
        let _ = symlink(base.join("circular_a"), base.join("circular_b"));

        // Many files (stress test)
        let many_dir = base.join("many_files");
        fs::create_dir(&many_dir).map_err(|e| e.to_string())?;
        for i in 0..200 {
            fs::write(many_dir.join(format!("file_{:04}.txt", i)), format!("content {}", i))
                .map_err(|e| e.to_string())?;
        }

        // Files with various extensions
        for ext in &["rs", "py", "c", "h", "o", "so", "a", "md", "toml", "json", "xml"] {
            fs::write(base.join(format!("sample.{}", ext)), "sample").map_err(|e| e.to_string())?;
        }

        Ok(Self { dir })
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_fixtures() {
        let fixtures = TestFixtures::create().unwrap();
        assert!(fixtures.path().join("normal.txt").exists());
        assert!(fixtures.path().join(".hidden").exists());
        assert!(fixtures.path().join("subdir").exists());
        assert!(fixtures.path().join("subdir/nested.txt").exists());
        assert!(fixtures.path().join("many_files").exists());
        assert!(fixtures.path().join("empty_dir").exists());
    }
}
