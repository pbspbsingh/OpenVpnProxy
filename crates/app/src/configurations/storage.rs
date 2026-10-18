//! A serialized caller writes one complete TOML record by atomic replacement.
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use super::SavedConfiguration;

const ACTIVE_FILE: &str = "active.toml";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveSelection {
    id: String,
}

const MAX_STORED_BYTES: u64 = 2 * 1024 * 1024;
pub(super) const MAX_CONFIGURATIONS: usize = 64;

pub(super) struct Repository {
    root: PathBuf,
}

impl Repository {
    pub(super) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub(super) async fn list(&self) -> Result<Vec<(String, SavedConfiguration)>> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            let directory = match std::fs::read_dir(&root) {
                Ok(directory) => directory,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
                Err(error) => return Err(error.into()),
            };
            let mut records = Vec::new();
            for entry in directory {
                let entry = entry?;
                let path = entry.path();
                if entry.file_name() == ACTIVE_FILE
                    || path.extension().is_none_or(|extension| extension != "toml")
                {
                    continue;
                }
                let id = path
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .filter(|id| valid_id(id))
                    .context("invalid configuration filename")?;
                if records.len() >= MAX_CONFIGURATIONS {
                    bail!("too many saved configurations");
                }
                records.push((id.to_owned(), read_record(&path)?));
            }
            records.sort_by_key(|(id, _)| id.parse::<u64>().unwrap_or_default());
            Ok(records)
        })
        .await?
    }

    pub(super) async fn save(
        &self,
        id: String,
        record: SavedConfiguration,
        guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<()> {
        if !valid_id(&id) {
            bail!("invalid configuration ID");
        }
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            // Keep serialization even if the HTTP request is cancelled mid-write.
            let _guard = guard;
            let bytes = toml::to_string(&record).context("cannot encode saved configuration")?;
            write_atomic(&root, &format!("{id}.toml"), &bytes)
        })
        .await?
    }

    pub(super) async fn load_active(&self) -> Result<Option<String>> {
        let path = self.root.join(ACTIVE_FILE);
        tokio::task::spawn_blocking(move || {
            let file = match std::fs::File::open(path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let mut text = String::new();
            file.take(4097).read_to_string(&mut text)?;
            if text.len() > 4096 {
                bail!("invalid last active configuration record");
            }
            let selection: ActiveSelection = toml::from_str(&text)
                .map_err(|_| anyhow::anyhow!("invalid last active configuration record"))?;
            if selection.id != "default" && !valid_id(&selection.id) {
                bail!("invalid last active configuration ID");
            }
            Ok(Some(selection.id))
        })
        .await?
    }

    pub(super) async fn save_active(
        &self,
        id: String,
        guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<()> {
        if id != "default" && !valid_id(&id) {
            bail!("invalid active configuration ID");
        }
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            let text = toml::to_string(&ActiveSelection { id })?;
            write_atomic(&root, ACTIVE_FILE, &text)
        })
        .await?
    }

    pub(super) async fn delete(
        &self,
        id: String,
        guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<()> {
        if !valid_id(&id) {
            bail!("invalid configuration ID");
        }
        let remembered = self.load_active().await?;
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            std::fs::remove_file(root.join(format!("{id}.toml")))?;
            if remembered.as_deref() == Some(&id) {
                std::fs::remove_file(root.join(ACTIVE_FILE))?;
            }
            #[cfg(unix)]
            std::fs::File::open(root)?.sync_all()?;
            Ok(())
        })
        .await?
    }
}

pub(super) fn valid_id(id: &str) -> bool {
    id.parse::<u64>()
        .is_ok_and(|number| number > 0 && number.to_string() == id)
}

fn read_record(path: &Path) -> Result<SavedConfiguration> {
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(MAX_STORED_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_STORED_BYTES {
        bail!("saved configuration is too large");
    }
    // Never attach TOML's source excerpts: these records contain credentials.
    toml::from_str(&text).map_err(|_| anyhow::anyhow!("invalid saved configuration"))
}

/// Every persisted record, including startup selection, uses the same durability policy.
fn write_atomic(root: &Path, name: &str, bytes: &str) -> Result<()> {
    let mut directory = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    match directory.create(root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    if bytes.len() as u64 > MAX_STORED_BYTES {
        bail!("saved configuration is too large");
    }
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temporary = root.join(format!(".{name}.{nonce}.tmp"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // A failed create must never remove somebody else's temporary file.
    let mut file = options.open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, root.join(name))?;
        #[cfg(unix)]
        std::fs::File::open(root)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}
