use super::*;
use ovpn_ui::ProfileUpload;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);
impl TestDirectory {
    fn new() -> Self {
        let number = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("ovpn-config-test-{}-{number}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn repository(&self) -> PathBuf {
        self.0.join("configs")
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn profile() -> String {
    format!(
        "client\nproto udp\nremote 127.0.0.1 9\nauth-user-pass\n<ca>\nCERT\n</ca>\n<tls-crypt>\n{}\n</tls-crypt>\n",
        "00".repeat(256)
    )
}

fn input(name: &str) -> ConfigurationInput {
    ConfigurationInput {
        name: name.into(),
        username: "vpn-user".into(),
        password: Some("private-password".into()),
        profile: Some(ProfileUpload {
            name: "client.ovpn".into(),
            content: profile(),
        }),
        revision: None,
        dns_override: None,
        dns_tls_name: None,
        max_active_vpn_hosts: None,
    }
}

fn edit(revision: u64) -> ConfigurationInput {
    ConfigurationInput {
        name: "Renamed".into(),
        username: "another-user".into(),
        password: None,
        profile: None,
        revision: Some(revision),
        dns_override: Some("1.1.1.1".parse().unwrap()),
        dns_tls_name: Some("cloudflare-dns.com".into()),
        max_active_vpn_hosts: NonZeroUsize::new(2),
    }
}

#[tokio::test]
async fn optional_default_starts_empty_and_reading_does_not_create_storage() {
    let directory = TestDirectory::new();
    let (service, _) = Configurations::new(None, directory.repository());
    let list = service.list().await.unwrap();
    assert!(list.configurations.is_empty());
    assert!(list.status.id.is_none());
    assert!(list.status.phase == ConfigurationPhase::Unconfigured);
    assert!(!directory.repository().exists());
    assert!(matches!(
        service.activate("default".into(), 1).await,
        Err(ConfigurationError::NotFound)
    ));
}

#[tokio::test]
async fn save_edit_and_reload_retain_secrets_but_only_return_metadata() {
    let directory = TestDirectory::new();
    let (service, _) = Configurations::new(None, directory.repository());
    let first = service.save(None, input("Ireland")).await.unwrap();
    assert!(storage::valid_id(&first.id));
    assert_eq!(first.revision, 1);
    let second = service.save(Some(first.id.clone()), edit(1)).await.unwrap();
    assert_eq!(second.revision, 2);
    assert!(second.password_set);
    assert_eq!(second.profile_name, "client.ovpn");
    assert!(
        service.status().phase == ConfigurationPhase::Unconfigured,
        "save activated the proxy"
    );
    drop(service);
    let (service, _) = Configurations::new(None, directory.repository());
    let records = service.records().await.unwrap();
    assert_eq!(records[0].1.openvpn_config.password, "private-password");
    assert_eq!(records[0].1.openvpn_config.profile_text, profile());
    let list = service.list().await.unwrap();
    assert_eq!(list.configurations[0].name, "Renamed");
    assert_eq!(
        list.configurations[0].dns_tls_name.as_deref(),
        Some("cloudflare-dns.com")
    );
    let metadata = toml::to_string(&list.configurations[0]).unwrap();
    assert!(!metadata.contains("private-password"));
    assert!(!metadata.contains("profile_text"));
    let stored =
        std::fs::read_to_string(directory.repository().join(format!("{}.toml", first.id))).unwrap();
    assert!(stored.contains("[openvpn_config]"));
    assert_eq!(
        std::fs::read_dir(directory.repository()).unwrap().count(),
        1
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(directory.repository().join(format!("{}.toml", first.id)))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(directory.repository())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}

#[tokio::test]
async fn default_is_optional_read_only_and_separate_from_saved_files() {
    let directory = TestDirectory::new();
    let path = directory.0.join("default.ovpn");
    std::fs::write(&path, profile()).unwrap();
    let default = OpenVpnConfig {
        profile_path: path,
        username: "default-user".into(),
        password: "default-secret".into(),
        dns_override: None,
        dns_tls_name: None,
        max_active_vpn_hosts: None,
    };
    let (service, _) = Configurations::new(Some(default), directory.repository());
    let list = service.list().await.unwrap();
    assert_eq!(list.configurations[0].id, "default");
    assert!(list.configurations[0].read_only);
    assert!(matches!(
        service.save(Some("default".into()), input("Changed")).await,
        Err(ConfigurationError::ReadOnly)
    ));
    assert!(!directory.repository().exists());
    service.failed(&anyhow::anyhow!("startup failed"));
    assert!(matches!(
        service.activate("default".into(), 99).await,
        Err(ConfigurationError::Conflict)
    ));
}

#[tokio::test]
async fn revisions_prevent_lost_edits_and_stale_activation() {
    let directory = TestDirectory::new();
    let (service, _requests) = Configurations::new(None, directory.repository());
    let first = service.save(None, input("Ireland")).await.unwrap();
    service.save(Some(first.id.clone()), edit(1)).await.unwrap();
    assert!(matches!(
        service.save(Some(first.id.clone()), edit(1)).await,
        Err(ConfigurationError::Conflict)
    ));
    assert!(matches!(
        service.activate(first.id.clone(), 1).await,
        Err(ConfigurationError::Conflict)
    ));
    assert!(service.status().phase == ConfigurationPhase::Unconfigured);
    assert_eq!(service.records().await.unwrap()[0].1.revision, 2);
}

#[tokio::test]
async fn activation_uses_an_immutable_revision_and_is_serialized() {
    let directory = TestDirectory::new();
    let (service, mut requests) = Configurations::new(None, directory.repository());
    let first = service.save(None, input("Ireland")).await.unwrap();
    service
        .activate(first.id.clone(), first.revision)
        .await
        .unwrap();
    assert!(service.status().phase == ConfigurationPhase::Starting);
    assert!(matches!(
        service.activate(first.id.clone(), first.revision).await,
        Err(ConfigurationError::Busy)
    ));
    let activation = requests.recv().await.unwrap();
    service.save(Some(first.id.clone()), edit(1)).await.unwrap();
    assert_eq!(activation.prepared.username, "vpn-user");
    assert_eq!(service.status().revision, Some(1));
    service.ready().await.unwrap();
    assert_eq!(service.list().await.unwrap().configurations[0].revision, 2);
    service.activate(first.id, 2).await.unwrap();
    assert_eq!(
        requests.recv().await.unwrap().prepared.username,
        "another-user"
    );
    assert_eq!(service.status().generation, 2);
}

#[tokio::test]
async fn invalid_input_and_failed_validation_leave_saved_and_running_state_intact() {
    let directory = TestDirectory::new();
    let (service, _requests) = Configurations::new(None, directory.repository());
    let first = service.save(None, input("Ireland")).await.unwrap();
    let original =
        std::fs::read(directory.repository().join(format!("{}.toml", first.id))).unwrap();
    for change in 0..7 {
        let mut value = edit(1);
        match change {
            0 => value.password = Some(String::new()),
            1 => {
                value.profile = Some(ProfileUpload {
                    name: "bad.ovpn".into(),
                    content: "PRIVATE_KEY invalid".into(),
                })
            }
            2 => value.max_active_vpn_hosts = NonZeroUsize::new(65),
            3 => value.name = "Default".into(),
            4 => value.dns_tls_name = Some("https://bad/name".into()),
            5 => value.dns_override = Some("0.0.0.0".parse().unwrap()),
            _ => {
                value.profile = Some(ProfileUpload {
                    name: "../outside.ovpn".into(),
                    content: profile(),
                })
            }
        }
        let error = service
            .save(Some(first.id.clone()), value)
            .await
            .err()
            .unwrap();
        assert!(!error.to_string().contains("PRIVATE_KEY"));
        assert_eq!(
            std::fs::read(directory.repository().join(format!("{}.toml", first.id))).unwrap(),
            original
        );
    }
    assert!(matches!(
        service.save(Some("../outside".into()), edit(1)).await,
        Err(ConfigurationError::NotFound)
    ));
    assert!(service.status().phase == ConfigurationPhase::Unconfigured);
}

#[tokio::test]
async fn concurrent_edits_only_commit_one_revision() {
    let directory = TestDirectory::new();
    let (service, _) = Configurations::new(None, directory.repository());
    let saved = service.save(None, input("Ireland")).await.unwrap();
    let (first, second) = tokio::join!(
        service.save(Some(saved.id.clone()), edit(1)),
        service.save(Some(saved.id.clone()), edit(1))
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(service.records().await.unwrap()[0].1.revision, 2);
}

#[tokio::test]
async fn edits_can_replace_profiles_and_passwords_or_clear_unneeded_credentials() {
    let directory = TestDirectory::new();
    let (service, _) = Configurations::new(None, directory.repository());
    let saved = service.save(None, input("Ireland")).await.unwrap();
    let mut replacement = edit(1);
    replacement.password = Some("replacement-password".into());
    replacement.profile = Some(ProfileUpload {
        name: "replacement.ovpn".into(),
        content: profile().replace("auth-user-pass\n", ""),
    });
    let saved = service
        .save(Some(saved.id.clone()), replacement)
        .await
        .unwrap();
    assert_eq!(saved.profile_name, "replacement.ovpn");
    assert_eq!(
        service.records().await.unwrap()[0]
            .1
            .openvpn_config
            .password,
        "replacement-password"
    );
    let mut cleared = edit(2);
    cleared.password = Some(String::new());
    cleared.username.clear();
    assert!(
        !service
            .save(Some(saved.id.clone()), cleared)
            .await
            .unwrap()
            .password_set
    );
    assert!(
        service.records().await.unwrap()[0]
            .1
            .openvpn_config
            .password
            .is_empty()
    );
}

#[test]
fn cancelling_a_queued_disk_commit_keeps_its_write_lock_until_completion() {
    use std::future::Future;
    use std::task::{Context, Waker};
    let directory = TestDirectory::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (started, running) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            blocked.recv().unwrap();
        });
        running.await.unwrap();
        let gate = Arc::new(Mutex::new(()));
        let guard = Arc::clone(&gate).lock_owned().await;
        let repository = Repository::new(directory.repository());
        let record = SavedConfiguration {
            name: "Saved despite cancellation".into(),
            revision: 1,
            openvpn_config: SavedOpenVpnConfig {
                username: "user".into(),
                password: "secret".into(),
                profile_name: "client.ovpn".into(),
                profile_text: profile(),
                dns_override: None,
                dns_tls_name: None,
                max_active_vpn_hosts: None,
            },
        };
        let mut saving = Box::pin(repository.save("1".into(), record, guard));
        assert!(
            saving
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(saving);
        assert!(
            gate.try_lock().is_err(),
            "cancelled request released an unfinished commit's lock"
        );
        release.send(()).unwrap();
        blocker.await.unwrap();
        let _guard = tokio::time::timeout(std::time::Duration::from_secs(5), gate.lock())
            .await
            .unwrap();
        assert!(directory.repository().join("1.toml").exists());
    });
}

#[tokio::test]
async fn unavailable_activation_receiver_does_not_change_selection() {
    let directory = TestDirectory::new();
    let (service, requests) = Configurations::new(None, directory.repository());
    let saved = service.save(None, input("Ireland")).await.unwrap();
    drop(requests);
    assert!(matches!(
        service.activate(saved.id.clone(), 1).await,
        Err(ConfigurationError::Unavailable)
    ));
    assert!(service.status().phase == ConfigurationPhase::Unconfigured);
    assert!(service.status().id.is_none());
}

#[tokio::test]
async fn startup_restores_last_successful_identity_using_latest_saved_settings() {
    let directory = TestDirectory::new();
    let (service, mut requests) = Configurations::new(None, directory.repository());
    let first = service.save(None, input("First")).await.unwrap();
    service.activate(first.id.clone(), 1).await.unwrap();
    requests.recv().await.unwrap();
    service.ready().await.unwrap();
    service.save(Some(first.id.clone()), edit(1)).await.unwrap();
    let second = service.save(None, input("Second")).await.unwrap();
    service.activate(second.id, 1).await.unwrap();
    requests.recv().await.unwrap();
    service.failed(&anyhow::anyhow!("second configuration failed to start"));
    let state = std::fs::read_to_string(directory.repository().join("active.toml")).unwrap();
    let state: toml::Value = toml::from_str(&state).unwrap();
    assert_eq!(
        state.as_table().unwrap().len(),
        1,
        "startup selection preserved configuration contents"
    );
    assert_eq!(state["id"].as_str(), Some(first.id.as_str()));
    let default = OpenVpnConfig {
        profile_path: directory.0.join("absent-default.ovpn"),
        username: "default".into(),
        password: "default".into(),
        dns_override: None,
        dns_tls_name: None,
        max_active_vpn_hosts: None,
    };
    let (restarted, _) = Configurations::new(Some(default), directory.repository());
    let prepared = restarted.prepare_startup().await.unwrap().unwrap();
    assert_eq!(prepared.username, "another-user");
    assert_eq!(restarted.status().id.as_deref(), Some(first.id.as_str()));
    assert_eq!(restarted.status().revision, Some(2));
    assert_eq!(
        restarted.list().await.unwrap().configurations.len(),
        3,
        "startup metadata appeared in the configuration list"
    );
}

#[tokio::test]
async fn default_is_only_used_when_no_successful_selection_has_been_saved() {
    let directory = TestDirectory::new();
    let profile_path = directory.0.join("default.ovpn");
    std::fs::write(&profile_path, profile()).unwrap();
    let default = OpenVpnConfig {
        profile_path,
        username: "default-user".into(),
        password: "default-password".into(),
        dns_override: None,
        dns_tls_name: None,
        max_active_vpn_hosts: None,
    };
    let (service, _) = Configurations::new(Some(default), directory.repository());
    assert_eq!(
        service.prepare_startup().await.unwrap().unwrap().username,
        "default-user"
    );
    service.ready().await.unwrap();
    let (restarted, _) = Configurations::new(None, directory.repository());
    let error = restarted.prepare_startup().await.err().unwrap();
    assert!(matches!(error, ConfigurationError::MissingFile(_)));
    restarted.failed(&error.into());
    assert!(restarted.status().file_missing);
}

#[tokio::test]
async fn deleting_inactive_entries_protects_running_and_default_configs_and_never_reuses_ids() {
    let directory = TestDirectory::new();
    let (service, mut requests) = Configurations::new(None, directory.repository());
    let active = service.save(None, input("Active")).await.unwrap();
    let other = service.save(None, input("Other")).await.unwrap();
    service.activate(active.id.clone(), 1).await.unwrap();
    requests.recv().await.unwrap();
    assert!(matches!(
        service.delete(active.id.clone(), 1).await,
        Err(ConfigurationError::InUse)
    ));
    service.ready().await.unwrap();
    assert!(matches!(
        service.delete(active.id.clone(), 1).await,
        Err(ConfigurationError::InUse)
    ));
    assert!(matches!(
        service.delete("default".into(), 1).await,
        Err(ConfigurationError::ReadOnly)
    ));
    assert!(matches!(
        service.delete(other.id.clone(), 2).await,
        Err(ConfigurationError::Conflict)
    ));
    service.delete(other.id.clone(), 1).await.unwrap();
    let replacement = service.save(None, input("Replacement")).await.unwrap();
    assert_ne!(replacement.id, other.id);
    assert!(matches!(
        service.save(Some(other.id.clone()), edit(1)).await,
        Err(ConfigurationError::NotFound)
    ));
    assert_eq!(
        service
            .inner
            .repository
            .load_active()
            .await
            .unwrap()
            .as_deref(),
        Some(active.id.as_str())
    );
    service.failed(&anyhow::anyhow!("session ended"));
    service.delete(active.id, 1).await.unwrap();
    assert!(
        service
            .inner
            .repository
            .load_active()
            .await
            .unwrap()
            .is_none()
    );
    assert!(service.status().phase == ConfigurationPhase::Unconfigured);
    let (restarted, _) = Configurations::new(None, directory.repository());
    assert!(restarted.prepare_startup().await.unwrap().is_none());
}

#[tokio::test]
async fn missing_last_active_file_is_reported_instead_of_using_another_configuration() {
    let directory = TestDirectory::new();
    let (service, mut requests) = Configurations::new(None, directory.repository());
    let saved = service.save(None, input("Active")).await.unwrap();
    service.activate(saved.id.clone(), 1).await.unwrap();
    requests.recv().await.unwrap();
    service.ready().await.unwrap();
    std::fs::remove_file(directory.repository().join(format!("{}.toml", saved.id))).unwrap();
    service.save(None, input("Other")).await.unwrap();
    let (restarted, _) = Configurations::new(None, directory.repository());
    let error = restarted.prepare_startup().await.err().unwrap();
    assert!(matches!(error, ConfigurationError::MissingFile(_)));
    restarted.failed(&error.into());
    assert!(restarted.status().file_missing);
    assert_eq!(restarted.status().id.as_deref(), Some(saved.id.as_str()));
}

#[tokio::test]
async fn a_previous_sessions_failure_cannot_unlock_the_next_configuration() {
    let directory = TestDirectory::new();
    let (service, mut requests) = Configurations::new(None, directory.repository());
    let first = service.save(None, input("First")).await.unwrap();
    let second = service.save(None, input("Second")).await.unwrap();
    service.activate(first.id, 1).await.unwrap();
    requests.recv().await.unwrap();
    service.ready().await.unwrap();
    let old_generation = service.status().generation;
    service.activate(second.id.clone(), 1).await.unwrap();
    assert!(!service.failed_for(old_generation, &anyhow::anyhow!("old session failed")));
    assert!(service.status().phase == ConfigurationPhase::Starting);
    assert_eq!(service.status().id.as_deref(), Some(second.id.as_str()));
    assert!(matches!(
        service.delete(second.id, 1).await,
        Err(ConfigurationError::InUse)
    ));
}
