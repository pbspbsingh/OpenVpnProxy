//! Saved VPN configurations and activation requests, independent of HTTP serving.
mod storage;

use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use ovpn_profile::Profile;
use ovpn_ui::{
    ConfigurationControl, ConfigurationError, ConfigurationFuture, ConfigurationInput,
    ConfigurationList, ConfigurationPhase, ConfigurationStatus, ConfigurationSummary,
};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::sync::{Mutex, mpsc, watch};

use crate::config::OpenVpnConfig;
use storage::{MAX_CONFIGURATIONS, Repository};

pub(crate) const MAX_PROFILE_BYTES: usize = 256 * 1024;
const DEFAULT_ID: &str = "default";

/// Runtime inputs are prepared and validated before disturbing the current proxy.
pub(crate) struct PreparedConfiguration {
    pub profile: Profile,
    pub username: String,
    pub password: String,
    pub dns_override: Option<Ipv4Addr>,
    pub max_active_vpn_hosts: Option<NonZeroUsize>,
}

pub(crate) struct Activation {
    pub prepared: PreparedConfiguration,
}

#[derive(Clone)]
pub(crate) struct Configurations {
    inner: Arc<Inner>,
}

struct Inner {
    default: Option<OpenVpnConfig>,
    repository: Repository,
    // Serializes read/modify/write and activation acceptance, never packet work.
    gate: Arc<Mutex<()>>,
    requests: mpsc::Sender<Activation>,
    status: watch::Sender<ConfigurationStatus>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedConfiguration {
    name: String,
    revision: u64,
    openvpn_config: SavedOpenVpnConfig,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedOpenVpnConfig {
    username: String,
    password: String,
    profile_name: String,
    profile_text: String,
    dns_override: Option<Ipv4Addr>,
    max_active_vpn_hosts: Option<NonZeroUsize>,
}

impl Configurations {
    pub(crate) fn new(
        default: Option<OpenVpnConfig>,
        root: PathBuf,
    ) -> (Self, mpsc::Receiver<Activation>) {
        let (requests, receiver) = mpsc::channel(1);
        let configured = default.is_some();
        let (status, _) = watch::channel(ConfigurationStatus {
            id: configured.then(|| DEFAULT_ID.to_owned()),
            name: configured.then(|| "Default".to_owned()),
            revision: configured.then_some(1),
            generation: u64::from(configured),
            phase: if configured {
                ConfigurationPhase::Starting
            } else {
                ConfigurationPhase::Unconfigured
            },
            message: None,
            file_missing: false,
        });
        (
            Self {
                inner: Arc::new(Inner {
                    default,
                    repository: Repository::new(root),
                    gate: Arc::new(Mutex::new(())),
                    requests,
                    status,
                }),
            },
            receiver,
        )
    }

    pub(crate) fn status(&self) -> ConfigurationStatus {
        self.inner.status.borrow().clone()
    }

    pub(crate) fn starting(&self) {
        self.inner.status.send_modify(|state| {
            state.phase = ConfigurationPhase::Starting;
            state.message = None;
            state.file_missing = false;
        });
    }

    /// Remember the selection only after proxy initialization has succeeded.
    pub(crate) async fn ready(&self) -> Result<(), ConfigurationError> {
        let guard = Arc::clone(&self.inner.gate).lock_owned().await;
        let id = self.status().id.ok_or(ConfigurationError::NotFound)?;
        self.inner
            .repository
            .save_active(id, guard)
            .await
            .map_err(storage_error)?;
        self.inner.status.send_modify(|state| {
            state.phase = ConfigurationPhase::Ready;
            state.message = None;
            state.file_missing = false;
        });
        Ok(())
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<ConfigurationStatus> {
        self.inner.status.subscribe()
    }

    /// Resolve startup identity before preparing any VPN. A missing remembered
    /// entry is an error rather than an implicit change of egress identity.
    pub(crate) async fn prepare_startup(
        &self,
    ) -> Result<Option<PreparedConfiguration>, ConfigurationError> {
        let _guard = self.inner.gate.lock().await;
        let remembered = self
            .inner
            .repository
            .load_active()
            .await
            .map_err(storage_error)?;
        let id = remembered.or_else(|| self.inner.default.as_ref().map(|_| DEFAULT_ID.to_owned()));
        let Some(id) = id else {
            self.inner
                .status
                .send_replace(ConfigurationStatus::default());
            return Ok(None);
        };
        self.inner.status.send_replace(ConfigurationStatus {
            name: Some(if id == DEFAULT_ID {
                "Default".into()
            } else {
                format!("Configuration {id}")
            }),
            id: Some(id.clone()),
            revision: None,
            generation: 1,
            phase: ConfigurationPhase::Starting,
            message: None,
            file_missing: false,
        });
        let (name, revision, prepared) = self.load_selection(&id).await.map_err(
            |error| match error {
                ConfigurationError::NotFound => {
                    ConfigurationError::MissingFile(if id == DEFAULT_ID {
                        "The last active Default configuration is missing from [openvpn_config]."
                            .into()
                    } else {
                        format!("The last active configuration file is missing: {id}.toml")
                    })
                }
                error => error,
            },
        )?;
        self.inner.status.send_modify(|state| {
            state.name = Some(name);
            state.revision = Some(revision);
        });
        Ok(Some(prepared))
    }

    async fn load_selection(
        &self,
        id: &str,
    ) -> Result<(String, u64, PreparedConfiguration), ConfigurationError> {
        if id == DEFAULT_ID {
            let default = self
                .inner
                .default
                .as_ref()
                .ok_or(ConfigurationError::NotFound)?;
            return Ok(("Default".into(), 1, prepare_default(default).await?));
        }
        let (_, record) = self
            .records()
            .await?
            .into_iter()
            .find(|(key, _)| key == id)
            .ok_or(ConfigurationError::NotFound)?;
        let vpn = &record.openvpn_config;
        let prepared = prepare(
            &vpn.profile_text,
            &vpn.username,
            &vpn.password,
            vpn.dns_override,
            vpn.max_active_vpn_hosts,
        )?;
        Ok((record.name, record.revision, prepared))
    }

    pub(crate) fn failed(&self, error: &anyhow::Error) {
        self.failed_for(self.status().generation, error);
    }

    pub(crate) fn failed_for(&self, generation: u64, error: &anyhow::Error) -> bool {
        let mut applied = false;
        self.inner.status.send_modify(|state| {
            if state.generation != generation {
                return;
            }
            state.phase = ConfigurationPhase::Failed;
            state.message = Some(format!("{error:#}"));
            state.file_missing = matches!(
                error.downcast_ref::<ConfigurationError>(),
                Some(ConfigurationError::MissingFile(_))
            );
            applied = true;
        });
        applied
    }

    async fn records(&self) -> Result<Vec<(String, SavedConfiguration)>, ConfigurationError> {
        self.inner.repository.list().await.map_err(|error| {
            tracing::error!(%error, "cannot read configuration storage");
            ConfigurationError::Storage
        })
    }

    async fn save_record(
        &self,
        id: Option<String>,
        input: ConfigurationInput,
    ) -> Result<ConfigurationSummary, ConfigurationError> {
        if id.as_deref() == Some(DEFAULT_ID) {
            return Err(ConfigurationError::ReadOnly);
        }
        let guard = Arc::clone(&self.inner.gate).lock_owned().await;
        let records = self.records().await?;
        let previous = match &id {
            Some(id) => Some(
                &records
                    .iter()
                    .find(|(key, _)| key == id)
                    .ok_or(ConfigurationError::NotFound)?
                    .1,
            ),
            None => None,
        };
        if input.revision != previous.map(|record| record.revision) {
            return Err(ConfigurationError::Conflict);
        }
        if previous.is_none() && records.len() >= MAX_CONFIGURATIONS {
            return invalid("At most 64 custom configurations can be saved");
        }
        let name = input.name.trim().to_owned();
        if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
            return invalid("Name must contain 1–80 bytes without control characters");
        }
        if name.eq_ignore_ascii_case("default")
            || records.iter().any(|(key, record)| {
                Some(key) != id.as_ref() && record.name.eq_ignore_ascii_case(&name)
            })
        {
            return invalid("Choose a unique configuration name other than Default");
        }
        let password = input
            .password
            .or_else(|| previous.map(|record| record.openvpn_config.password.clone()))
            .unwrap_or_default();
        let (profile_name, profile_text) = match input.profile {
            Some(upload) => {
                if upload.name.is_empty()
                    || upload.name.len() > 255
                    || upload.name.contains(['/', '\\'])
                    || upload.name.chars().any(char::is_control)
                {
                    return invalid("Choose a valid OpenVPN filename");
                }
                (upload.name, upload.content)
            }
            None => previous
                .map(|record| {
                    (
                        record.openvpn_config.profile_name.clone(),
                        record.openvpn_config.profile_text.clone(),
                    )
                })
                .ok_or_else(|| ConfigurationError::Invalid("An OpenVPN file is required".into()))?,
        };
        prepare(
            &profile_text,
            &input.username,
            &password,
            input.dns_override,
            input.max_active_vpn_hosts,
        )?;
        let revision = previous
            .map_or(Some(1), |record| record.revision.checked_add(1))
            .ok_or(ConfigurationError::Conflict)?;
        let id = match id {
            Some(id) => id,
            None => new_id(&records)?,
        };
        let record = SavedConfiguration {
            name,
            revision,
            openvpn_config: SavedOpenVpnConfig {
                username: input.username,
                password,
                profile_name,
                profile_text,
                dns_override: input.dns_override,
                max_active_vpn_hosts: input.max_active_vpn_hosts,
            },
        };
        let summary = record.summary(id.clone());
        self.inner
            .repository
            .save(id, record, guard)
            .await
            .map_err(|error| {
                tracing::error!(%error, "cannot save configuration");
                ConfigurationError::Storage
            })?;
        Ok(summary)
    }

    async fn request_activation(
        &self,
        id: String,
        revision: u64,
    ) -> Result<(), ConfigurationError> {
        let _guard = self.inner.gate.lock().await;
        if self.inner.status.borrow().phase == ConfigurationPhase::Starting {
            return Err(ConfigurationError::Busy);
        }
        let (name, current_revision, prepared) = self.load_selection(&id).await?;
        if revision != current_revision {
            return Err(ConfigurationError::Conflict);
        }
        let old = self.inner.status.borrow().clone();
        self.inner.status.send_replace(ConfigurationStatus {
            id: Some(id),
            name: Some(name),
            revision: Some(revision),
            generation: old.generation.saturating_add(1),
            phase: ConfigurationPhase::Starting,
            message: None,
            file_missing: false,
        });
        if self
            .inner
            .requests
            .try_send(Activation { prepared })
            .is_err()
        {
            self.inner.status.send_replace(old);
            return Err(ConfigurationError::Unavailable);
        }
        Ok(())
    }

    async fn delete_record(&self, id: String, revision: u64) -> Result<(), ConfigurationError> {
        if id == DEFAULT_ID {
            return Err(ConfigurationError::ReadOnly);
        }
        let guard = Arc::clone(&self.inner.gate).lock_owned().await;
        let status = self.status();
        if status.id.as_deref() == Some(&id)
            && matches!(
                status.phase,
                ConfigurationPhase::Ready | ConfigurationPhase::Starting
            )
        {
            return Err(ConfigurationError::InUse);
        }
        let records = self.records().await?;
        let record = &records
            .iter()
            .find(|(key, _)| key == &id)
            .ok_or(ConfigurationError::NotFound)?
            .1;
        if record.revision != revision {
            return Err(ConfigurationError::Conflict);
        }
        self.inner
            .repository
            .delete(id.clone(), guard)
            .await
            .map_err(storage_error)?;
        self.inner.status.send_modify(|current| {
            if current.id.as_deref() == Some(&id) && current.generation == status.generation {
                *current = ConfigurationStatus {
                    generation: status.generation.saturating_add(1),
                    ..ConfigurationStatus::default()
                };
            }
        });
        Ok(())
    }
}

impl ConfigurationControl for Configurations {
    fn list(&self) -> ConfigurationFuture<'_, ConfigurationList> {
        Box::pin(async move {
            let _guard = self.inner.gate.lock().await;
            let mut configurations = vec![];
            if let Some(default) = &self.inner.default {
                configurations.push(ConfigurationSummary {
                    id: DEFAULT_ID.into(),
                    name: "Default".into(),
                    read_only: true,
                    revision: 1,
                    username: default.username.clone(),
                    password_set: !default.password.is_empty(),
                    profile_name: default
                        .profile_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                    dns_override: default.dns_override,
                    max_active_vpn_hosts: default.max_active_vpn_hosts,
                });
            }
            configurations.extend(
                self.records()
                    .await?
                    .into_iter()
                    .map(|(id, record)| record.summary(id)),
            );
            Ok(ConfigurationList {
                configurations,
                status: self.inner.status.borrow().clone(),
            })
        })
    }

    fn save(
        &self,
        id: Option<String>,
        input: ConfigurationInput,
    ) -> ConfigurationFuture<'_, ConfigurationSummary> {
        Box::pin(self.save_record(id, input))
    }

    fn activate(&self, id: String, revision: u64) -> ConfigurationFuture<'_, ()> {
        Box::pin(self.request_activation(id, revision))
    }

    fn delete(&self, id: String, revision: u64) -> ConfigurationFuture<'_, ()> {
        Box::pin(self.delete_record(id, revision))
    }
}

impl SavedConfiguration {
    fn summary(&self, id: String) -> ConfigurationSummary {
        ConfigurationSummary {
            id,
            name: self.name.clone(),
            read_only: false,
            revision: self.revision,
            username: self.openvpn_config.username.clone(),
            password_set: !self.openvpn_config.password.is_empty(),
            profile_name: self.openvpn_config.profile_name.clone(),
            dns_override: self.openvpn_config.dns_override,
            max_active_vpn_hosts: self.openvpn_config.max_active_vpn_hosts,
        }
    }
}

pub(crate) async fn prepare_default(
    config: &OpenVpnConfig,
) -> Result<PreparedConfiguration, ConfigurationError> {
    let file = tokio::fs::File::open(&config.profile_path)
        .await
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ConfigurationError::MissingFile(format!(
                    "OpenVPN profile file is missing: {}",
                    config.profile_path.display()
                ))
            } else {
                ConfigurationError::Invalid("Cannot read the default OpenVPN file".into())
            }
        })?;
    let mut content = String::new();
    file.take(MAX_PROFILE_BYTES as u64 + 1)
        .read_to_string(&mut content)
        .await
        .map_err(|_| ConfigurationError::Invalid("Cannot read the default OpenVPN file".into()))?;
    prepare(
        &content,
        &config.username,
        &config.password,
        config.dns_override,
        config.max_active_vpn_hosts,
    )
}

fn prepare(
    text: &str,
    username: &str,
    password: &str,
    dns_override: Option<Ipv4Addr>,
    max_active_vpn_hosts: Option<NonZeroUsize>,
) -> Result<PreparedConfiguration, ConfigurationError> {
    if text.len() > MAX_PROFILE_BYTES {
        return invalid("OpenVPN files must be at most 256 KiB");
    }
    if username.len() > 4096
        || password.len() > 4096
        || username.contains('\0')
        || password.contains('\0')
    {
        return invalid("Credentials must be at most 4096 bytes and contain no NUL characters");
    }
    if max_active_vpn_hosts.is_some_and(|limit| limit.get() > 64) {
        return invalid("Active host limit must be between 1 and 64");
    }
    let profile = Profile::parse(text).map_err(|error| {
        // Unknown directive names can themselves contain pasted secret material.
        let message = match error {
            ovpn_profile::ProfileError::UnsupportedDirective(_) => {
                "OpenVPN profile contains an unsupported directive".into()
            }
            error => error.to_string(),
        };
        ConfigurationError::Invalid(message)
    })?;
    if profile.remotes.len() > 64 {
        return invalid("OpenVPN profiles may contain at most 64 remotes");
    }
    if profile.needs_credentials && (username.is_empty() || password.is_empty()) {
        return invalid("This OpenVPN profile requires a username and password");
    }
    Ok(PreparedConfiguration {
        profile,
        username: username.to_owned(),
        password: password.to_owned(),
        dns_override,
        max_active_vpn_hosts,
    })
}

fn storage_error(error: anyhow::Error) -> ConfigurationError {
    tracing::error!(%error, "configuration storage operation failed");
    ConfigurationError::Storage
}

// IDs must not be reused after deletion: an old browser must never edit a new entry.
fn new_id(records: &[(String, SavedConfiguration)]) -> Result<String, ConfigurationError> {
    for _ in 0..8 {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes).map_err(|_| ConfigurationError::Storage)?;
        let id = u64::from_ne_bytes(bytes);
        if id != 0 && !records.iter().any(|(key, _)| key == &id.to_string()) {
            return Ok(id.to_string());
        }
    }
    Err(ConfigurationError::Storage)
}

fn invalid<T>(message: &str) -> Result<T, ConfigurationError> {
    Err(ConfigurationError::Invalid(message.into()))
}

#[cfg(test)]
mod tests;
