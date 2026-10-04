# Google Cloud Secret Manager authentication

ramenv uses Application Default Credentials (ADC) for Google Cloud initialization
and runtime commands. It never writes credentials to workspace or key-reference
files. `GoogleKeyStore` in `src/services.rs` creates its client with
`SecretManagerService::builder().build().await`.

The Google Cloud Rust SDK selects credentials, acquires tokens, and refreshes
them. ramenv has no custom Google Cloud credential resolver or
`RAMENV_GOOGLE_CREDENTIAL` setting.

## Automatic selection

ADC searches in this order:

1. **`GOOGLE_APPLICATION_CREDENTIALS`**: a path to a credential JSON file. The
   installed Rust authentication library supports user credentials, service
   account keys, impersonated service accounts, and supported external-account
   federation configuration.
2. **Local ADC credentials** created by
   `gcloud auth application-default login`, normally stored at:
   - Linux/macOS: `$HOME/.config/gcloud/application_default_credentials.json`
   - Windows: `%APPDATA%\gcloud\application_default_credentials.json`
3. **The metadata service** when no credential file is configured or found at
   the local ADC location. Supported Google Cloud environments expose an
   attached service account or workload identity through this service.

ADC uses discovery order to select credentials; it does not compare identities'
permissions. A configured credential file or a local ADC file takes precedence
over a deployed workload's metadata identity.

See Google's [Application Default Credentials documentation](https://cloud.google.com/docs/authentication/application-default-credentials)
for the search order and deployment setup.

## Local development

Create local ADC credentials:

```sh
gcloud auth application-default login
ramenv init workspace --ingredient google
```

`gcloud auth login` signs in the gcloud CLI. Use
`gcloud auth application-default login` to create the credentials ramenv reads.
Changing the CLI's active account does not change an existing ADC file.

If `GOOGLE_APPLICATION_CREDENTIALS` points to another identity, unset it before
using local ADC. To replace or refresh your local ADC login, run
`gcloud auth application-default login` again.

Initialization asks for a Google Cloud project ID and accepts `my-project` or
`projects/my-project`. ramenv stores `projects/my-project` in the `provider_location`
field of `.ramenv.keyrefs.toml`. It stores secrets in this project, regardless
of the gcloud CLI's active project or ADC's quota project.

### Service account impersonation

To develop using a service account without downloading its private key:

```sh
gcloud auth application-default login \
  --impersonate-service-account=ramenv@my-project.iam.gserviceaccount.com
ramenv init workspace --ingredient google
```

Your user needs permission to generate access tokens for that service account,
usually through `roles/iam.serviceAccountTokenCreator` on the account. The
impersonated account needs the Secret Manager permissions below.

### Quota project

If Google reports that user ADC has no quota project, configure one:

```sh
gcloud auth application-default set-quota-project my-project
```

The identity needs `serviceusage.services.use` on that quota project. The quota
project does not change the project where ramenv stores secrets.

## Explicit selection

Select credentials through ADC configuration:

| Setting or command | Behavior |
| --- | --- |
| `GOOGLE_APPLICATION_CREDENTIALS` | Select the credential JSON file to load before local ADC or metadata. |
| `gcloud auth application-default login` | Create local user ADC credentials. |
| `gcloud auth application-default login --impersonate-service-account=EMAIL` | Create ADC credentials that impersonate a service account. |
| `GOOGLE_CLOUD_QUOTA_PROJECT` | Override the SDK's quota/billing project; does not select an identity or secret-storage project. |

To use an external credential configuration file:

```sh
export GOOGLE_APPLICATION_CREDENTIALS=/absolute/path/to/credentials.json
ramenv init workspace --ingredient google
```

Prefer federation or impersonation over long-lived service account keys. Keep
credential files outside the repository and do not copy them into ramenv's
workspace files.

For Google Cloud deployments, attach a service account with the required Secret
Manager permissions or configure the platform's supported workload identity.
Leave `GOOGLE_APPLICATION_CREDENTIALS` unset and do not package a local ADC file
when the deployment should use metadata credentials. Federation outside Google
Cloud uses an external-account configuration file supported by the SDK.

The Google authentication library handles metadata requests and token refresh.
ramenv does not run Azure-style VM discovery or add its own metadata probe.

## Required permissions and API setup

Enable the Secret Manager API in the project that stores the secrets. An
administrator with service-enablement permissions can run:

```sh
gcloud services enable secretmanager.googleapis.com --project=my-project
```

The gcloud command uses the CLI's credentials, not ramenv's ADC credentials.

The identity selected by ADC needs these permissions:

| Operation | Permission |
| --- | --- |
| Create a key's secret | `secretmanager.secrets.create` |
| Add a new key version | `secretmanager.versions.add` |
| Load a pinned key version | `secretmanager.versions.access` |
| Remove a key's secret | `secretmanager.secrets.delete` |

`roles/secretmanager.secretAccessor` permits reads only. Initialization, updates,
and removal need additional permissions. `roles/secretmanager.admin` includes
all the permissions above and more; prefer a custom role limited to what ramenv
needs where practical.

Secret creation requires permissions on the parent project. Scope access to
existing secrets where possible. On Compute Engine, OAuth access scopes can
also limit API access. Give the workload suitable scopes, such as
`cloud-platform`, in addition to IAM permissions.

## Failure policy

A missing file explicitly selected by `GOOGLE_APPLICATION_CREDENTIALS`, an
unreadable file, invalid JSON, or unsupported credential configuration returns
an error instead of falling back to local ADC or metadata. A missing file at
the default local ADC location allows metadata fallback; a malformed or
unreadable file there returns an error.

Token acquisition failures and an unavailable metadata service return errors.
ramenv does not try another identity after credential selection. A Secret
Manager `PermissionDenied` response does not trigger a different ADC source.
Grant the selected identity access to the saved project, verify that the API is
enabled, and check any quota-project requirements.

A successful ADC login does not verify Secret Manager access. The selected
identity still needs the permissions above.

## Key references and deletion

ramenv stores numeric version references in `.ramenv.keyrefs.toml`, using the
form `projects/<project>/secrets/<secret>/versions/<version>`. It keeps raw key
values out of the file and checks references against the saved project. Reads
select the pinned version, never `latest`. Updates add a new version and save
its reference. ramenv writes local references only after the pending remote
operations succeed.

New secrets use automatic replication. Removing a key deletes the entire
secret and all its versions. Deleting a secret that no longer exists is treated
as success.

All three cloud providers use the same secret-name format: a normalized ASCII
prefix of up to 62 characters, a hyphen, and a 64-character SHA-256 suffix. ramenv
hashes the full `ramenv-{workspace_name}-{kind}-{key}` string before normalizing
or truncating it, so those changes do not merge distinct names.

For other providers, see [Azure authentication](azure-authentication.md) and
[AWS authentication](aws-authentication.md).
