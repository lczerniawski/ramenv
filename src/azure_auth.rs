//! Shared Azure authentication policy for initialization and runtime commands.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use azure_core::credentials::TokenCredential;
use azure_identity::{
    ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential,
    ManagedIdentityCredentialOptions, UserAssignedId, WorkloadIdentityCredential,
    WorkloadIdentityCredentialOptions,
};

const IMDS_COMPUTE_URL: &str =
    "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01";
const IMDS_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_METADATA_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialKind {
    ClientSecret,
    WorkloadIdentity,
    ManagedIdentity,
    DeveloperTools,
    Discover,
}

// Intentionally not Debug: this configuration contains a client secret.
struct CredentialConfig {
    kind: CredentialKind,
    tenant_id: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    token_file: Option<String>,
}

impl CredentialConfig {
    fn from_env(mut get: impl FnMut(&str) -> Result<Option<String>>) -> Result<Self> {
        let override_kind = get("RAMENV_AZURE_CREDENTIAL")?;
        let mut config = Self {
            kind: CredentialKind::Discover,
            tenant_id: get("AZURE_TENANT_ID")?,
            client_id: get("AZURE_CLIENT_ID")?,
            client_secret: get("AZURE_CLIENT_SECRET")?,
            token_file: get("AZURE_FEDERATED_TOKEN_FILE")?,
        };
        config.kind = match override_kind.as_deref() {
            None | Some("auto") => {
                let mut hosted_identity = false;
                for name in [
                    "IDENTITY_ENDPOINT",
                    "IDENTITY_HEADER",
                    "IDENTITY_SERVER_THUMBPRINT",
                    "IMDS_ENDPOINT",
                    "MSI_ENDPOINT",
                    "MSI_SECRET",
                ] {
                    hosted_identity |= get(name)?.is_some();
                }
                if config.client_secret.is_some() {
                    CredentialKind::ClientSecret
                } else if config.token_file.is_some() {
                    CredentialKind::WorkloadIdentity
                } else if hosted_identity
                    || (config.client_id.is_some() && config.tenant_id.is_none())
                {
                    CredentialKind::ManagedIdentity
                } else if config.tenant_id.is_some() {
                    bail!(
                        "incomplete Azure identity configuration: set AZURE_TENANT_ID and \
                         AZURE_CLIENT_ID with AZURE_CLIENT_SECRET or AZURE_FEDERATED_TOKEN_FILE; \
                         alternatively select RAMENV_AZURE_CREDENTIAL explicitly"
                    );
                } else {
                    CredentialKind::Discover
                }
            }
            Some("client-secret") => CredentialKind::ClientSecret,
            Some("workload-identity") => CredentialKind::WorkloadIdentity,
            Some("managed-identity") => CredentialKind::ManagedIdentity,
            Some("developer-tools") => CredentialKind::DeveloperTools,
            Some(_) => bail!(
                "RAMENV_AZURE_CREDENTIAL must be auto, client-secret, workload-identity, \
                 managed-identity, or developer-tools"
            ),
        };
        config.validate()?;
        Ok(config)
    }

    fn required<'a>(value: &'a Option<String>, name: &str) -> Result<&'a str> {
        value
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .with_context(|| {
                format!("{name} must be set and non-empty for the selected Azure credential")
            })
    }

    fn validate(&self) -> Result<()> {
        match self.kind {
            CredentialKind::ClientSecret | CredentialKind::WorkloadIdentity => {
                Self::required(&self.tenant_id, "AZURE_TENANT_ID")?;
                Self::required(&self.client_id, "AZURE_CLIENT_ID")?;
                if self.kind == CredentialKind::ClientSecret {
                    Self::required(&self.client_secret, "AZURE_CLIENT_SECRET")?;
                } else {
                    Self::required(&self.token_file, "AZURE_FEDERATED_TOKEN_FILE")?;
                }
            }
            CredentialKind::ManagedIdentity if self.client_id.is_some() => {
                Self::required(&self.client_id, "AZURE_CLIENT_ID")?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn resolve(
        &self,
        probe: impl std::future::Future<Output = Result<bool>>,
    ) -> Result<Arc<dyn TokenCredential>> {
        let kind = if self.kind == CredentialKind::Discover {
            if probe.await? {
                CredentialKind::ManagedIdentity
            } else {
                CredentialKind::DeveloperTools
            }
        } else {
            self.kind
        };
        self.build(kind)
    }

    fn build(&self, kind: CredentialKind) -> Result<Arc<dyn TokenCredential>> {
        let credential: Arc<dyn TokenCredential> = match kind {
            CredentialKind::ClientSecret => ClientSecretCredential::new(
                Self::required(&self.tenant_id, "AZURE_TENANT_ID")?,
                Self::required(&self.client_id, "AZURE_CLIENT_ID")?.to_owned(),
                Self::required(&self.client_secret, "AZURE_CLIENT_SECRET")?
                    .to_owned()
                    .into(),
                None,
            )
            .context("failed to configure Azure client-secret authentication")?,
            CredentialKind::WorkloadIdentity => {
                WorkloadIdentityCredential::new(Some(WorkloadIdentityCredentialOptions {
                    tenant_id: Some(Self::required(&self.tenant_id, "AZURE_TENANT_ID")?.to_owned()),
                    client_id: Some(Self::required(&self.client_id, "AZURE_CLIENT_ID")?.to_owned()),
                    token_file_path: Some(
                        Self::required(&self.token_file, "AZURE_FEDERATED_TOKEN_FILE")?.into(),
                    ),
                    ..Default::default()
                }))
                .context("failed to configure Azure workload identity authentication")?
            }
            CredentialKind::ManagedIdentity => {
                ManagedIdentityCredential::new(Some(ManagedIdentityCredentialOptions {
                    user_assigned_id: self.client_id.clone().map(UserAssignedId::ClientId),
                    ..Default::default()
                }))
                .context("failed to configure Azure managed identity authentication")?
            }
            CredentialKind::DeveloperTools => DeveloperToolsCredential::new(None)
                .context("failed to configure Azure developer-tools authentication")?,
            CredentialKind::Discover => {
                bail!("Azure credential discovery must finish before construction")
            }
        };
        log::debug!("Azure authentication selected {kind:?}");
        Ok(credential)
    }
}

/// Select a single identity. Once selected, token failures propagate instead of
/// silently switching to another account. DeveloperToolsCredential supplies its
/// own Azure CLI -> Azure Developer CLI fallback and caches its successful source.
pub(crate) async fn azure_credential() -> Result<Arc<dyn TokenCredential>> {
    let config = CredentialConfig::from_env(|name| match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} must contain valid Unicode"),
    })?;
    config
        .resolve(probe_managed_identity(IMDS_COMPUTE_URL, IMDS_PROBE_TIMEOUT))
        .await
}

// Probe metadata, not a token: finding an Azure VM selects managed identity even
// if that VM's identity is missing/broken. Such token failures must not use CLI.
async fn probe_managed_identity(url: &str, timeout: Duration) -> Result<bool> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(timeout)
        .build()
        .context("failed to create Azure managed identity discovery client")?;
    let Ok(mut response) = client.get(url).header("Metadata", "true").send().await else {
        return Ok(false);
    };
    if !response.status().is_success() {
        return Ok(false);
    }
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if body.len() + chunk.len() <= MAX_METADATA_BYTES => {
                body.extend_from_slice(&chunk)
            }
            Ok(None) => break,
            _ => return Ok(false),
        }
    }
    let Ok(metadata) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return Ok(false);
    };
    Ok(metadata["azEnvironment"]
        .as_str()
        // IMDS examples use AZUREPUBLICCLOUD; accept Azure cloud prefixes in
        // either case without assuming the string is ASCII or allocating.
        .and_then(|cloud| cloud.get(.."Azure".len()))
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Azure"))
        && metadata["vmId"].as_str().is_some_and(|id| !id.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn config(vars: &[(&str, &str)]) -> Result<CredentialConfig> {
        CredentialConfig::from_env(|name| {
            Ok(vars
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned()))
        })
    }

    #[test]
    fn discovers_when_nothing_is_configured() {
        assert_eq!(config(&[]).unwrap().kind, CredentialKind::Discover);
    }

    #[test]
    fn client_secret_precedes_workload_and_hosted_identity() {
        let config = config(&[
            ("AZURE_TENANT_ID", "tenant"),
            ("AZURE_CLIENT_ID", "client"),
            ("AZURE_CLIENT_SECRET", "secret"),
            ("AZURE_FEDERATED_TOKEN_FILE", "/token"),
            ("IDENTITY_ENDPOINT", "http://localhost"),
        ])
        .unwrap();
        assert_eq!(config.kind, CredentialKind::ClientSecret);
    }

    #[test]
    fn workload_precedes_hosted_identity() {
        let config = config(&[
            ("AZURE_TENANT_ID", "tenant"),
            ("AZURE_CLIENT_ID", "client"),
            ("AZURE_FEDERATED_TOKEN_FILE", "/token"),
            ("IDENTITY_ENDPOINT", "http://localhost"),
        ])
        .unwrap();
        assert_eq!(config.kind, CredentialKind::WorkloadIdentity);
    }

    #[test]
    fn detects_hosted_and_user_assigned_identity() {
        for name in [
            "IDENTITY_ENDPOINT",
            "IDENTITY_HEADER",
            "IDENTITY_SERVER_THUMBPRINT",
            "IMDS_ENDPOINT",
            "MSI_ENDPOINT",
            "MSI_SECRET",
            "AZURE_CLIENT_ID",
        ] {
            assert_eq!(
                config(&[(name, "configured")]).unwrap().kind,
                CredentialKind::ManagedIdentity,
                "{name}"
            );
        }
    }

    #[test]
    fn rejects_partial_or_empty_identity_configuration() {
        let cases: &[(&[(&str, &str)], &str)] = &[
            (
                &[("AZURE_CLIENT_SECRET", "sensitive-value")],
                "AZURE_TENANT_ID",
            ),
            (
                &[
                    ("AZURE_TENANT_ID", "tenant"),
                    ("AZURE_CLIENT_SECRET", "secret"),
                ],
                "AZURE_CLIENT_ID",
            ),
            (
                &[
                    ("AZURE_TENANT_ID", "tenant"),
                    ("AZURE_CLIENT_ID", "client"),
                    ("AZURE_CLIENT_SECRET", " "),
                ],
                "AZURE_CLIENT_SECRET",
            ),
            (
                &[("AZURE_FEDERATED_TOKEN_FILE", "/token")],
                "AZURE_TENANT_ID",
            ),
            (
                &[
                    ("AZURE_TENANT_ID", "tenant"),
                    ("AZURE_CLIENT_ID", "client"),
                    ("AZURE_FEDERATED_TOKEN_FILE", ""),
                ],
                "AZURE_FEDERATED_TOKEN_FILE",
            ),
            (
                &[("AZURE_TENANT_ID", "tenant")],
                "incomplete Azure identity configuration",
            ),
            (
                &[("AZURE_TENANT_ID", "tenant"), ("AZURE_CLIENT_ID", "client")],
                "incomplete Azure identity configuration",
            ),
            (&[("AZURE_CLIENT_ID", "")], "AZURE_CLIENT_ID"),
        ];
        for (vars, message) in cases {
            let error = config(vars).err().unwrap().to_string();
            assert!(error.contains(message), "{error}");
            assert!(!error.contains("sensitive-value"));
        }
    }

    #[test]
    fn supports_explicit_overrides_and_rejects_invalid_values() {
        for (value, expected) in [
            ("auto", CredentialKind::Discover),
            ("managed-identity", CredentialKind::ManagedIdentity),
            ("developer-tools", CredentialKind::DeveloperTools),
        ] {
            assert_eq!(
                config(&[("RAMENV_AZURE_CREDENTIAL", value)]).unwrap().kind,
                expected
            );
        }
        assert_eq!(
            config(&[
                ("RAMENV_AZURE_CREDENTIAL", "developer-tools"),
                ("AZURE_CLIENT_SECRET", "otherwise-incomplete")
            ])
            .unwrap()
            .kind,
            CredentialKind::DeveloperTools
        );
        for value in ["client-secret", "workload-identity"] {
            assert!(config(&[("RAMENV_AZURE_CREDENTIAL", value)]).is_err());
        }
        assert!(config(&[("RAMENV_AZURE_CREDENTIAL", "unknown")]).is_err());
    }

    #[tokio::test]
    async fn configured_identity_skips_discovery() {
        let config = config(&[
            ("AZURE_TENANT_ID", "tenant"),
            ("AZURE_CLIENT_ID", "client"),
            ("AZURE_CLIENT_SECRET", "secret"),
        ])
        .unwrap();
        let credential = config
            .resolve(async { panic!("must not probe configured identities") })
            .await
            .unwrap();
        assert!(format!("{credential:?}").contains("ClientSecretCredential"));
    }

    #[tokio::test]
    async fn broken_workload_identity_does_not_fall_back() {
        let missing =
            std::env::temp_dir().join(format!("ramenv-missing-token-{}", std::process::id()));
        let config = config(&[
            ("AZURE_TENANT_ID", "tenant"),
            ("AZURE_CLIENT_ID", "client"),
            ("AZURE_FEDERATED_TOKEN_FILE", missing.to_str().unwrap()),
        ])
        .unwrap();
        let error = config
            .resolve(async { panic!("must not probe configured identities") })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("workload identity"));
    }

    #[tokio::test]
    async fn absent_vm_selects_developer_tools() {
        let credential = config(&[])
            .unwrap()
            .resolve(async { Ok(false) })
            .await
            .unwrap();
        assert!(format!("{credential:?}").contains("DeveloperToolsCredential"));
    }

    #[tokio::test]
    async fn discovered_vm_selects_managed_identity() {
        let credential = config(&[])
            .unwrap()
            .resolve(async { Ok(true) })
            .await
            .unwrap();
        assert!(format!("{credential:?}").contains("ManagedIdentityCredential"));
    }

    #[tokio::test]
    async fn discovery_setup_failure_does_not_fall_back() {
        let error = config(&[])
            .unwrap()
            .resolve(async { bail!("probe setup failed") })
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "probe setup failed");
    }

    fn server(response: String, delay: Duration) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/metadata", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            assert!(
                String::from_utf8(request)
                    .unwrap()
                    .to_lowercase()
                    .contains("metadata: true")
            );
            let (headers, body) = response.split_once("\r\n\r\n").unwrap();
            stream.write_all(headers.as_bytes()).unwrap();
            stream.write_all(b"\r\n\r\n").unwrap();
            thread::sleep(delay);
            // A timed-out client may already have closed the connection.
            let _ = stream.write_all(body.as_bytes());
        });
        (url, handle)
    }

    #[tokio::test]
    async fn probe_requires_azure_metadata_and_does_not_follow_redirects() {
        for (status, headers, body, expected) in [
            (
                "200 OK",
                "",
                r#"{"azEnvironment":"AzurePublicCloud","vmId":"vm-id"}"#,
                true,
            ),
            (
                "200 OK",
                "",
                r#"{"azEnvironment":"OtherCloud","vmId":"vm-id"}"#,
                false,
            ),
            (
                "200 OK",
                "",
                r#"{"azEnvironment":"AzurePublicCloud"}"#,
                false,
            ),
            (
                "200 OK",
                "",
                r#"{"azEnvironment":"AZUREPUBLICCLOUD","vmId":""}"#,
                false,
            ),
            (
                "200 OK",
                "",
                r#"{"azEnvironment":"AZUREPUBLICCLOUD"}"#,
                false,
            ),
            (
                "200 OK",
                "",
                r#"{"azEnvironment":"AZUR","vmId":"vm-id"}"#,
                false,
            ),
            (
                "200 OK",
                "",
                r#"{"azEnvironment":"☁️AzurePublicCloud","vmId":"vm-id"}"#,
                false,
            ),
            ("200 OK", "", "not json", false),
            ("401 Unauthorized", "", "", false),
            ("302 Found", "Location: http://127.0.0.1:1/\r\n", "", false),
        ] {
            let (url, handle) = server(
                format!(
                    "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ),
                Duration::ZERO,
            );
            assert_eq!(
                probe_managed_identity(&url, Duration::from_secs(2))
                    .await
                    .unwrap(),
                expected
            );
            handle.join().unwrap();
        }
    }

    #[tokio::test]
    async fn probe_recognizes_azure_cloud_names_case_insensitively() {
        for cloud in [
            "AZUREPUBLICCLOUD",
            "AZUREUSGOVERNMENTCLOUD",
            "AZURECHINACLOUD",
            "AZUREGERMANCLOUD",
            "AzurePublicCloud",
            "azurepubliccloud",
            "aZuRePublicCloud",
        ] {
            let body = format!(r#"{{"azEnvironment":"{cloud}","vmId":"vm-id"}}"#);
            let (url, handle) = server(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ),
                Duration::ZERO,
            );
            let recognized = probe_managed_identity(&url, Duration::from_secs(2))
                .await
                .unwrap();
            handle.join().unwrap();
            assert!(recognized, "Azure cloud {cloud} must be recognized");
        }
    }

    #[tokio::test]
    async fn probe_does_not_contact_a_redirect_target() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let (url, handle) = server(
            format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{}/\r\nContent-Length: 0\r\n\r\n",
                target.local_addr().unwrap()
            ),
            Duration::ZERO,
        );
        assert!(
            !probe_managed_identity(&url, Duration::from_millis(100))
                .await
                .unwrap()
        );
        handle.join().unwrap();
        assert_eq!(
            target.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn unavailable_endpoint_is_not_an_identity() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        drop(listener);
        assert!(
            !probe_managed_identity(&url, Duration::from_millis(100))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn probe_bounds_response_size() {
        let body = " ".repeat(MAX_METADATA_BYTES + 1);
        let (url, handle) = server(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
            Duration::ZERO,
        );
        assert!(
            !probe_managed_identity(&url, Duration::from_secs(2))
                .await
                .unwrap()
        );
        handle.join().unwrap();
    }

    #[tokio::test]
    async fn probe_timeout_includes_reading_the_body() {
        // Valid metadata arrives after the deadline, although headers are immediate.
        let body = r#"{"azEnvironment":"AzurePublicCloud","vmId":"vm-id"}"#;
        let (url, handle) = server(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
            Duration::from_millis(200),
        );
        assert!(
            !probe_managed_identity(&url, Duration::from_millis(20))
                .await
                .unwrap()
        );
        handle.join().unwrap();
    }
}
