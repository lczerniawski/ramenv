# AWS Secrets Manager authentication

ramenv uses the AWS SDK's default credential provider chain for initialization
and runtime commands. It never writes credentials to workspace or key-reference
files. `AwsKeyStore` in `src/services.rs` loads its configuration with
`aws_config::defaults(BehaviorVersion::latest())`.

The SDK selects, acquires, caches, and refreshes credentials. ramenv has no
custom AWS credential resolver or `RAMENV_AWS_CREDENTIAL` setting.

## Automatic selection

The installed AWS Rust SDK searches in this order:

1. **Environment variables**: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`,
   with `AWS_SESSION_TOKEN` for temporary credentials.
2. **Shared profiles** in `~/.aws/config` and `~/.aws/credentials`. The SDK uses
   `AWS_PROFILE`, or the `default` profile when it is unset. Profiles can provide
   access keys, IAM Identity Center (SSO) credentials, assume-role configuration,
   or credentials from `credential_process`.
3. **Web identity tokens**: workload configuration such as `AWS_ROLE_ARN` and
   `AWS_WEB_IDENTITY_TOKEN_FILE`, commonly supplied by EKS IAM roles for service
   accounts (IRSA).
4. **Container credential endpoints**: ECS task roles and compatible endpoint
   configuration, including EKS Pod Identity.
5. **EC2 instance metadata**: the instance profile obtained through IMDSv2.

The SDK uses the first provider that returns credentials. It does not rank
identities by their permissions or retry another identity after a Secrets
Manager authorization failure. Environment credentials take precedence over
`AWS_PROFILE`; a local profile can take precedence over a workload identity.

See the [AWS Rust SDK credential provider documentation](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credential-providers.html)
for SDK behavior and supported configuration.

## Local development

### IAM Identity Center (SSO)

Configure a profile once, then log in before using ramenv:

```sh
aws configure sso --profile dev
aws sso login --profile dev
export AWS_PROFILE=dev
ramenv init workspace --ingredient aws
```

If access-key environment variables are left over from another session, unset
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` before
selecting a profile. When the SSO login session expires, run
`aws sso login --profile dev` again.

### Access-key profiles

For an account that uses access keys:

```sh
aws configure --profile dev
export AWS_PROFILE=dev
ramenv init workspace --ingredient aws
```

Temporary credentials also require a session token. Prefer SSO or temporary
role credentials over long-lived access keys. Keep shared credential files
outside the repository.

Initialization asks for a region such as `us-east-1`. ramenv stores it in the
`provider_location` field of `.ramenv.keyrefs.toml` and uses that region for Secrets
Manager operations. The saved workspace region takes precedence over the
SDK's default region configuration; changing `AWS_REGION` does not move the
workspace's secrets.

## Explicit selection

Select credentials through standard AWS configuration:

| Setting | Behavior |
| --- | --- |
| `AWS_PROFILE` | Select a shared profile; environment access keys still take precedence. |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Supply access-key credentials directly. |
| `AWS_SESSION_TOKEN` | Supply the session token required by temporary access-key credentials. |
| `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE` | Override the shared configuration and credentials file paths. |
| `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE` | Configure the SDK's web identity provider. |
| `AWS_EC2_METADATA_DISABLED=true` | Disable the SDK's EC2 metadata credential lookup. |

For AWS deployments, attach a role to the instance, task, or workload and let
the platform supply its credentials. Do not ship personal profiles or access
keys with the deployment. Remove higher-priority credential configuration when
the workload must use its attached role.

The AWS SDK handles metadata requests and their timeouts. ramenv does not run
Azure-style VM discovery or impose Azure's one-second probe timeout.

## Required permissions

The selected identity needs these permissions for ramenv secrets:

| Operation | Permission |
| --- | --- |
| Create a key's secret | `secretsmanager:CreateSecret` |
| Update a key with a new version | `secretsmanager:PutSecretValue` |
| Load a pinned key version | `secretsmanager:GetSecretValue` |
| Remove a key's secret | `secretsmanager:DeleteSecret` |

Scope access to the intended account, region, and ramenv secrets. Resource
policies, service control policies, and explicit denies can restrict access
beyond the identity's IAM policy. A customer-managed KMS key can also require
KMS permissions and an appropriate key policy.

## Failure policy

The SDK tries the next provider when a provider reports that credentials are
not loaded. Other provider errors stop the chain. ramenv adds no fallback.

Expired sessions, invalid credentials, unreachable credential endpoints, and
Secrets Manager access errors return errors. An `AccessDeniedException` does
not cause ramenv to try a different profile or role. Correct the selected
identity's configuration or permissions instead.

A successful login does not verify access to Secrets Manager. The selected
identity needs the permissions above in the workspace's saved region.

## Key references and deletion

ramenv stores `ARN#VersionId` references in `.ramenv.keyrefs.toml` and keeps raw
key values out of the file. It checks references against the saved region and
reads the exact version. Updates write a new version and save its reference.
ramenv writes local references only after the pending remote operations succeed.

Removing a key schedules deletion of the entire secret using AWS's default
recovery window; ramenv does not force immediate deletion. A secret pending
deletion must be restored or permanently deleted before its name can be reused.
Deleting a secret that no longer exists is treated as success.

All three cloud providers use the same secret-name format: a normalized ASCII
prefix of up to 62 characters, a hyphen, and a 64-character SHA-256 suffix. ramenv
hashes the full `ramenv-{workspace_name}-{kind}-{key}` string before normalizing
or truncating it, so those changes do not merge distinct names.

For other providers, see [Azure authentication](azure-authentication.md) and
[Google Cloud authentication](gcloud-authentication.md).
