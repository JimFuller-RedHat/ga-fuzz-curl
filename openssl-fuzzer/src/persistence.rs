use anyhow::Result;
use rusqlite::{params, Connection};

pub struct FuzzDatabase {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct RunRecord {
    pub generation: usize,
    pub individual_id: usize,
    pub openssl_command: String,
    pub fitness_total: f64,
    pub fitness_components: String,
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub duration_ms: u64,
    pub stdout: String,
    pub stderr: String,
    pub created_at: Option<String>,
}

impl FuzzDatabase {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.create_tables()?;
        Ok(db)
    }

    #[allow(dead_code)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.create_tables()?;
        Ok(db)
    }

    fn create_tables(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                generation INTEGER NOT NULL,
                individual_id INTEGER NOT NULL,
                openssl_command TEXT NOT NULL,
                fitness_total REAL NOT NULL,
                fitness_components TEXT NOT NULL,
                exit_code INTEGER NOT NULL,
                signal INTEGER,
                duration_ms INTEGER NOT NULL,
                stdout TEXT NOT NULL,
                stderr TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;
        Ok(())
    }

    pub fn insert_run(&self, run: &RunRecord) -> Result<()> {
        self.conn.execute(
            "INSERT INTO runs (
                generation, individual_id, openssl_command, fitness_total,
                fitness_components, exit_code, signal, duration_ms, stdout, stderr
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                run.generation,
                run.individual_id,
                run.openssl_command,
                run.fitness_total,
                run.fitness_components,
                run.exit_code,
                run.signal,
                run.duration_ms,
                run.stdout,
                run.stderr,
            ],
        )?;
        Ok(())
    }

    pub fn get_top_findings(&self, limit: usize) -> Result<Vec<RunRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT generation, individual_id, openssl_command, fitness_total,
                    fitness_components, exit_code, signal, duration_ms, stdout, stderr,
                    created_at
             FROM runs
             ORDER BY fitness_total DESC
             LIMIT ?1",
        )?;

        let records = stmt
            .query_map([limit], |row| {
                Ok(RunRecord {
                    generation: row.get(0)?,
                    individual_id: row.get(1)?,
                    openssl_command: row.get(2)?,
                    fitness_total: row.get(3)?,
                    fitness_components: row.get(4)?,
                    exit_code: row.get(5)?,
                    signal: row.get(6)?,
                    duration_ms: row.get(7)?,
                    stdout: row.get(8)?,
                    stderr: row.get(9)?,
                    created_at: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }

    #[allow(dead_code)]
    pub fn get_generation_stats(&self, generation: usize) -> Result<GenerationStats> {
        let mut stmt = self.conn.prepare(
            "SELECT COUNT(*), MAX(fitness_total), AVG(fitness_total), MIN(fitness_total)
             FROM runs
             WHERE generation = ?1",
        )?;

        let stats = stmt.query_row([generation], |row| {
            Ok(GenerationStats {
                count: row.get(0)?,
                max_fitness: row.get(1).unwrap_or(0.0),
                avg_fitness: row.get(2).unwrap_or(0.0),
                min_fitness: row.get(3).unwrap_or(0.0),
            })
        })?;

        Ok(stats)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct GenerationStats {
    pub count: usize,
    pub max_fitness: f64,
    pub avg_fitness: f64,
    pub min_fitness: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_db_in_memory() {
        let db = FuzzDatabase::open_in_memory().unwrap();
        assert!(db.conn.is_autocommit());
    }

    #[test]
    fn test_insert_and_query() {
        let db = FuzzDatabase::open_in_memory().unwrap();

        let run = RunRecord {
            generation: 1,
            individual_id: 0,
            openssl_command: "echo Q | openssl s_client -connect localhost:8443 -tls1_2".to_string(),
            fitness_total: 105.0,
            fitness_components: r#"{"crash":100.0,"timing":5.0}"#.to_string(),
            exit_code: -1,
            signal: Some(11),
            duration_ms: 5,
            stdout: String::new(),
            stderr: "Segmentation fault".to_string(),
            created_at: None,
        };

        db.insert_run(&run).unwrap();

        let results = db.get_top_findings(10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].generation, 1);
        assert_eq!(results[0].fitness_total, 105.0);
        assert!(results[0].openssl_command.contains("openssl"));
    }

    #[test]
    fn test_generation_stats() {
        let db = FuzzDatabase::open_in_memory().unwrap();

        for i in 0..5 {
            let run = RunRecord {
                generation: 1,
                individual_id: i,
                openssl_command: format!("openssl command {}", i),
                fitness_total: (i as f64 + 1.0) * 10.0,
                fitness_components: "{}".to_string(),
                exit_code: 0,
                signal: None,
                duration_ms: 5,
                stdout: String::new(),
                stderr: String::new(),
                created_at: None,
            };
            db.insert_run(&run).unwrap();
        }

        let stats = db.get_generation_stats(1).unwrap();
        assert_eq!(stats.count, 5);
        assert_eq!(stats.max_fitness, 50.0);
        assert_eq!(stats.avg_fitness, 30.0);
        assert_eq!(stats.min_fitness, 10.0);
    }

    #[test]
    fn test_top_findings_ordering() {
        let db = FuzzDatabase::open_in_memory().unwrap();

        for i in 0..3 {
            let run = RunRecord {
                generation: 0,
                individual_id: i,
                openssl_command: format!("openssl -{}", i),
                fitness_total: (i as f64 + 1.0) * 10.0,
                fitness_components: "{}".to_string(),
                exit_code: 0,
                signal: None,
                duration_ms: 5,
                stdout: String::new(),
                stderr: String::new(),
                created_at: None,
            };
            db.insert_run(&run).unwrap();
        }

        let results = db.get_top_findings(2).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].fitness_total >= results[1].fitness_total);
    }
}
