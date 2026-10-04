# Azure Key Vault authentication

ramenv uses the same credential resolver for Azure initialization and runtime
commands. It never writes credentials to workspace or key-reference files.
`AzureKeyStore` in `src/services.rs` accepts an injected
`Arc<dyn TokenCredential>`.

ramenv selects the credential type through `src/azure_auth.rs`. The Azure SDK
acquires and refreshes tokens for the selected credential.

## Automatic selection

By default (`RAMENV_AZURE_CREDENTIAL=auto`, or unset), selection is:

1. **Client secret** when `AZURE_CLIENT_SECRET` is present. Requires non-empty
   `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET`.
2. **Kubernetes workload identity** when `AZURE_FEDERATED_TOKEN_FILE` is present.
   Requires non-empty `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and
   `AZURE_FEDERATED_TOKEN_FILE`. The SDK reads the service-account token file.
3. **Managed identity** when Azure hosting variables are present
   (`IDENTITY_ENDPOINT`, `IDENTITY_HEADER`, `IDENTITY_SERVER_THUMBPRINT`,
   `IMDS_ENDPOINT`, `MSI_ENDPOINT`, or `MSI_SECRET`), or when `AZURE_CLIENT_ID` is
   present without `AZURE_TENANT_ID`. `AZURE_CLIENT_ID` selects a user-assigned
   identity; otherwise the SDK uses a system-assigned identity. Hosting support
   is limited to what the installed Azure Rust SDK supports; unsupported hosts
   return an error rather than falling back to a personal account.
4. **VM discovery** if no identity is configured. ramenv makes one bounded
   request to Azure's Instance Metadata Service (IMDS). Recognized Azure VM
   metadata selects managed identity. An unavailable endpoint, an unsuccessful
   response, or unrecognized metadata selects developer tools instead. See
   [How VM discovery works](#how-vm-discovery-works) for the request and limits.
5. **Developer tools**: the SDK tries Azure CLI (`az login`), then Azure Developer
   CLI (`azd auth login`), and reuses the first successful tool.

Setting only `AZURE_TENANT_ID`, or setting tenant/client IDs without a secret or
federated token file, is treated as incomplete configuration. Empty values do
not count as an absent configuration. Use an explicit selection below if those
variables are intentionally present for another purpose.

## Local development

Sign in with Azure CLI and select developer-tool credentials:

```sh
az login
export RAMENV_AZURE_CREDENTIAL=developer-tools
ramenv init workspace --ingredient azure
```

Explicitly selecting `developer-tools` skips VM discovery and its possible
one-second delay. Without the override, configured service-principal or workload
identity variables take precedence over your CLI login. When the CLI login
session expires, run `az login` again.

Azure Developer CLI credentials from `azd auth login` are also supported. The
SDK tries Azure CLI first, so an existing Azure CLI login can take precedence
over Azure Developer CLI.

Initialization asks for a Key Vault URL such as
`https://my-vault.vault.azure.net/`. ramenv stores it in the `provider_location`
field of `.ramenv.keyrefs.toml` and uses it for secret writes and deletion.
Create the vault before initialization; ramenv does not provision it. Signing
in to a different account does not change the saved vault location.

## Explicit selection

Set `RAMENV_AZURE_CREDENTIAL` to one of:

| Value | Behavior |
| --- | --- |
| `auto` | Use the discovery policy above (default). |
| `client-secret` | Require the three service-principal variables. |
| `workload-identity` | Require the tenant, client, and federated token file variables. |
| `managed-identity` | Use managed identity without a discovery probe; optionally use `AZURE_CLIENT_ID`. |
| `developer-tools` | Use Azure CLI / Azure Developer CLI without a discovery probe. |

For an Azure VM or a supported App Service using system-assigned identity:

```sh
export RAMENV_AZURE_CREDENTIAL=managed-identity
```

For a user-assigned managed identity, also set `AZURE_CLIENT_ID` to its client ID.
Attach or enable the identity on the hosting resource and grant it Key Vault
access. Explicit selection skips discovery, so an unreachable IMDS endpoint
cannot cause ramenv to select a personal CLI account.

For Kubernetes workload identity, configure the platform's service-account
federation and token-file injection, then select `workload-identity` or leave
automatic selection enabled. Keep client secrets and token files outside the
repository and do not package personal CLI credentials with a deployment.

## Required permissions

The selected identity needs permission to read, write, and delete secrets in
the existing vault. For vaults using access policies, the required secret
permissions are:

| Operation | Access-policy permission |
| --- | --- |
| Create a key's secret | `set` |
| Update a key with a new version | `set` |
| Load a pinned key version | `get` |
| Remove a key's secret | `delete` |

For vaults using Azure RBAC, `Key Vault Secrets User` permits reads only.
`Key Vault Secrets Officer` includes the write and delete operations ramenv
needs, but also grants additional secret-management permissions. Prefer a
custom role limited to the required operations where practical, and scope
access to the intended vault.

`Key Vault Contributor` manages the vault resource but does not grant access to
secret contents. A successful CLI login does not verify secret access. The
vault's firewall and network configuration can also restrict access.

See Microsoft's [Key Vault RBAC guide](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide)
for data-plane roles and assignment scopes.

## Failure policy

Once ramenv selects a service principal, managed identity, or workload identity,
missing required configuration, unreadable workload token files, and
token-request failures return an error without falling back to developer tools.
A VM recognized during discovery uses managed identity even if its identity
has not been enabled. Enable the identity or choose a credential explicitly.

`AzureKeyStore` reuses the selected credential object for all Key Vault
operations. The SDK handles token acquisition and refresh. A Key Vault
`403 Forbidden` returns an authorization error without trying another identity.
Check the selected identity's Key Vault permissions and the vault's network
restrictions.

Certificates, custom assertions, and Azure Pipelines service connections are
not auto-discovered by this resolver; they require additional explicit inputs
and can be supplied through `AzureKeyStore`'s existing credential injection.

## Key references and deletion

ramenv stores versioned secret URIs in `.ramenv.keyrefs.toml`, using the form
`https://<vault>/secrets/<secret>/<version>`. It keeps raw key values out of the
file. Reads require HTTPS and use the vault and exact version in each saved
URI, never the latest version. Updates write a new version to the saved
`provider_location` and save the URI returned by Key Vault. ramenv writes local
references only after the pending remote operations succeed.

Removing a key deletes the entire secret and all its versions. Key Vault's
soft-delete retention and purge-protection settings apply; ramenv does not
purge the secret. A soft-deleted secret must be recovered, purged when allowed,
or retained until its retention period expires before its name can be reused.
A missing secret or a failed delete returns an error.

All three cloud providers use the same secret-name format: a normalized ASCII
prefix of up to 62 characters, a hyphen, and a 64-character SHA-256 suffix. ramenv
hashes the full `ramenv-{workspace_name}-{kind}-{key}` string before normalizing
or truncating it, so those changes do not merge distinct names.

See Microsoft's [Key Vault soft-delete documentation](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview)
for recovery, retention, and purge protection.

## How VM discovery works

### Why the IP address is hardcoded

`169.254.169.254` is Azure's documented link-local IMDS address. On an Azure VM,
requests to this address reach the metadata service without leaving the host.
The address is fixed, requires no DNS lookup, and is unreachable from the public
Internet. Azure's SDK uses the same address for VM managed-identity token requests.

Other cloud providers can use the same address, so ramenv checks the response's
Azure-specific fields before selecting managed identity.

### Request and response checks

When automatic selection finds no configured identity, ramenv sends:

```http
GET http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
Metadata: true
```

The probe:

- Bypasses HTTP proxies, does not follow redirects, and does not retry.
- Has a one-second timeout covering the request and reading the body.
- Accepts at most 64 KiB of response data.
- Requires a successful HTTP response containing valid JSON.
- Requires a string `azEnvironment` starting with `Azure`, compared
  case-insensitively, and a non-empty string `vmId`.

The prefix check accepts both `AZUREPUBLICCLOUD` (used in Azure's documentation)
and `AzurePublicCloud`, along with Azure US Government, China, and German cloud
names. It accepts any casing of the `Azure` prefix. Missing fields, an empty
`vmId`, non-Azure prefixes, invalid JSON, oversized responses, redirects, and
request/body-read failures cause the probe to reject the response.

IMDS requires `Metadata: true` to mark an intentional metadata request. The
header supplies no credentials. The probe relies on the returned metadata and
does not verify the host's identity cryptographically.

### Token acquisition

The probe checks for Azure VM metadata. It does not call the token endpoint or
Key Vault, check whether managed identity is enabled, or check access to the
vault. After selection, the Azure SDK obtains tokens through
`ManagedIdentityCredential` when a Key Vault operation needs them.

```text
No identity configuration
    -> IMDS probe
        -> recognized Azure VM: ManagedIdentityCredential
        -> unavailable or unrecognized: DeveloperToolsCredential

Selected managed identity fails to obtain a token
    -> error, never fallback to a personal CLI account
```

Client-secret, workload-identity, and configured managed-identity credentials
skip the VM probe. ramenv checks App Service hosting variables and Kubernetes
workload identity configuration before VM discovery. Other Azure hosting
platforms may use different identity endpoints.

See Microsoft's [Azure Instance Metadata Service documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
for the endpoint, required header, and proxy-bypass requirements.

For other providers, see [AWS authentication](aws-authentication.md) and
[Google Cloud authentication](gcloud-authentication.md).
