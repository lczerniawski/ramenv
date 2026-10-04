# 🍜 ramenv

Encrypted environment variables for single repositories and monorepos.

ramenv is a Rust CLI that stores application configuration in encrypted, version-controlled vaults. Keep encryption keys locally or in your cloud secret manager. ramenv decrypts values in memory and injects them into an application process without generating a decrypted `.env` file.

```sh
ramenv init
ramenv set development DATABASE_URL
ramenv run development -- python app.py
```

## What it does

- Encrypts secrets with AES-256-GCM, with a fresh nonce for each encrypted value.
- Checks vault integrity with HMAC-SHA256 before loading environment data.
- Supports monorepos with shared per-environment encryption keys and separate service vaults.
- Stores keys locally or in AWS, Azure, or Google Cloud.
- Validates configuration using required fields, types, bounds, and regex rules.
- Imports existing `.env` files, compares environments, and rotates keys across registered workspace vaults.
- Runs applications in any language without requiring a Node.js runtime for ramenv itself.

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Ingredients and documentation](#ingredients-and-documentation)
- [Workspace files](#workspace-files)
- [Monorepos](#monorepos)
- [Validation](#validation)
- [Command reference](#command-reference)
- [Security and key handling](#security-and-key-handling)
- [Contributing](#contributing)
- [License](#license)

## Installation

Install from crates.io with Cargo and a recent stable [Rust toolchain](https://www.rust-lang.org/tools/install):

```sh
cargo install ramenv --locked
ramenv --help
```

Make sure Cargo's binary directory (usually `~/.cargo/bin`) is on your `PATH`. ramenv uses Rust edition 2024; your toolchain must also support the dependencies in `Cargo.lock`.

To install from source instead:

```sh
git clone https://github.com/lczerniawski/ramenv.git
cd ramenv
cargo install --path . --locked
```

To build without installing, run these commands from the source directory:

```sh
cargo build --release --locked --bin ramenv
./target/release/ramenv --help
```

## Quick start

Run these commands from your application's directory, not the ramenv source directory.

### 1. Initialize a vault

```sh
ramenv init
```

This uses the `local` ingredient and creates a workspace, local keys, and a signed vault with empty `development` and `production` environments. It also adds `.env` and `.ramenv.keys` entries to `.gitignore`.

### 2. Add configuration

```sh
# Prompts for a masked secret value; encrypts it before saving.
ramenv set development DATABASE_URL

# Prompts for a non-secret value; stores it in plaintext.
ramenv set development PORT --plaintext
```

Enter values interactively; the command does not accept them as arguments. Use uppercase variable names because `ramenv run` uppercases names when injecting them into the process environment.

To import an existing `.env` file:

```sh
ramenv onboard development
```

Onboarding reads `.env` in the current directory and asks which variables to encrypt. It imports unselected values as plaintext. Imported values overwrite matching keys in the selected environment. The original `.env` file is not deleted; remove it yourself when it is no longer needed.

### 3. Inspect and validate

```sh
ramenv list development
ramenv validate development
```

Values are masked by default. Use `ramenv list development --reveal` only when you intend to display decrypted values in your terminal.

Newly added or imported variables receive required `string` validation rules. See [Validation](#validation) to customize them.

### 4. Run your application

```sh
ramenv run development -- python app.py
ramenv run development -- npm run dev
ramenv run production -- ./my-server --port 8080
```

The `--` separates ramenv's arguments from the application's arguments. Vault values override matching inherited environment variables; other inherited variables remain available. ramenv returns the application's exit code.

`run` does not validate configuration. Run `validate` separately. To validate before starting an application in a POSIX shell:

```sh
ramenv validate production && ramenv run production -- ./my-server
```

## Ingredients and documentation

An ingredient is the provider that stores your workspace's encryption and vault-signing keys. Cloud ingredients store only those keys in the cloud. Application values remain in `.ramenv.vault.toml`.

| Ingredient | Key storage | Detailed guide |
| --- | --- | --- |
| `local` (default) | Raw keys in `.ramenv.keys` at the workspace root | [Local keys](#local-keys) |
| `aws` | AWS Secrets Manager | [AWS authentication and permissions](docs/aws-authentication.md) |
| `azure` | Azure Key Vault | [Azure authentication and permissions](docs/azure-authentication.md) |
| `google` | Google Cloud Secret Manager | [Google Cloud authentication and permissions](docs/gcloud-authentication.md) |

List the available ingredients:

```sh
ramenv menu
```

Select one when initializing a new repository:

```sh
ramenv init --ingredient local
ramenv init --ingredient aws
ramenv init --ingredient azure
ramenv init --ingredient google
```

Choose one of these commands for your workspace. The selected ingredient is saved in `.ramenv.workspace.toml` and reused by runtime commands. Re-running `init` with another ingredient does not migrate an existing workspace.

For a monorepo, use `ramenv init workspace --ingredient <ingredient>` at the root, then initialize each service as shown [below](#monorepos).

### Cloud setup at a glance

Authenticate before initializing a cloud workspace:

- **AWS:** uses the AWS SDK's default credential provider chain. For local SSO development, run `aws sso login --profile dev` and select the profile with `AWS_PROFILE=dev`. Initialization prompts for the Secrets Manager region. [Read the AWS guide](docs/aws-authentication.md) for credential precedence, IAM permissions, version references, and deletion behavior.
- **Azure:** supports developer tools, client secrets, managed identity, and workload identity. For local development, run `az login` and set `RAMENV_AZURE_CREDENTIAL=developer-tools`. Initialization prompts for the URL of an existing Key Vault. [Read the Azure guide](docs/azure-authentication.md) for identity selection, vault permissions, VM discovery, and soft-delete behavior.
- **Google Cloud:** uses Application Default Credentials (ADC). For local development, run `gcloud auth application-default login`, not just `gcloud auth login`. Initialization prompts for the storage project ID; enable the Secret Manager API in that project. [Read the Google Cloud guide](docs/gcloud-authentication.md) for ADC selection, impersonation, IAM permissions, and API setup.

Cloud workspaces save version-pinned key references in `.ramenv.keyrefs.toml`. This file contains no raw keys or cloud credentials. A successful cloud login alone does not grant the permissions needed to create, read, update, or delete keys. Prefer workload identities for deployments, and consult the ingredient's guide before configuring CI/CD.

## Workspace files

| File | Purpose | Version-control guidance |
| --- | --- | --- |
| `.ramenv.workspace.toml` | Workspace name, schema version, and selected ingredient | Commit it. |
| `.ramenv.vault.toml` | Environment values, validation rules, and integrity metadata | Commit it after reviewing any plaintext values. |
| `.ramenv.keys` | Raw encryption and signing keys for the local ingredient | **Never commit it.** |
| `.ramenv.keyrefs.toml` | Cloud provider location and versioned key references | Can be committed; contains resource identifiers, not raw keys. |
| `.env` | Optional input for onboarding | Keep it out of version control; onboarding leaves it on disk. |

Encrypted values use a `secret:` prefix. Variable names, environment names, validation rules, and values explicitly stored as plaintext are visible to anyone who can read the vault.

## Monorepos

Initialize a shared workspace at the repository root, then a vault in each service directory:

```sh
# From the monorepo root:
ramenv init workspace --ingredient local
mkdir -p apps/api apps/web

(
  cd apps/api
  ramenv init service
  ramenv set development DATABASE_URL
)

(
  cd apps/web
  ramenv init service
  ramenv set development PUBLIC_API_URL --plaintext
)
```

The resulting local layout is:

```text
my-monorepo/
├── .ramenv.workspace.toml
├── .ramenv.keys                 # ignored; shared workspace keys
└── apps/
    ├── api/
    │   └── .ramenv.vault.toml
    └── web/
        └── .ramenv.vault.toml
```

Cloud workspaces use `.ramenv.keyrefs.toml` instead of `.ramenv.keys`.

Run ordinary vault commands from the directory containing that service's vault. ramenv discovers the workspace root by walking up the directory tree, but reads the vault in the current directory. Services share an encryption key for each environment and each vault has its own signing key; values are not automatically merged or inherited between services.

Both `development` and `production` are created in each new service vault. `create-env` creates a workspace key and an empty environment in the current vault only; it does not populate sibling vaults.

### Workspace-wide changes

Key rotation and environment removal affect every registered vault containing that environment, whether you run the command from the workspace root or a service directory:

```sh
ramenv rotate production
ramenv remove-env development
```

Multi-vault workspaces prompt for confirmation. For non-interactive use, explicitly consent with `--yes` (or `-y`):

```sh
ramenv rotate production --yes
ramenv remove-env development --yes
```

Rotation re-encrypts encrypted values while preserving plaintext values. Environment removal deletes the shared encryption key as well as that environment's data in affected vaults. Cloud-provider deletion and retention rules differ; see the ingredient guides before removing an environment.

## Validation

Validation rules live in the `[validation]` sections of `.ramenv.vault.toml`. Edit these sections directly to customize the default rules:

```toml
[validation.DATABASE_URL]
type = "uri"
required = true

[validation.PORT]
type = "port"
required = true

[validation.LOG_LEVEL]
type = "regex"
pattern = "^(debug|info|warn|error)$"
required = false

[validation.WORKERS]
type = "integer"
min_value = 1
max_value = 32
required = false
```

| Type | Supported constraints |
| --- | --- |
| `string` | Optional `min_len` and `max_len` (byte length) |
| `integer` | Optional `min_value` and `max_value` |
| `float` | Finite values only; optional `min_value` and `max_value` |
| `boolean` | `true` or `false` |
| `port` | Integer from 1 through 65535 |
| `uri` | A URI/URL accepted by the URL parser |
| `ip` | IPv4 or IPv6 address |
| `email` | Basic `@` presence and position checks, not full email-address validation |
| `regex` | A match against `pattern`; use anchors for a whole-value match |

`required` defaults to `true`. Rules apply to all environments in the current vault. Validation checks declared rules; it does not reject additional variables without rules.

```sh
ramenv validate development  # One environment in the current vault
ramenv validate              # All environments in the current vault
```

Validation decrypts encrypted values in memory and returns a nonzero exit code on failure. Validation rules are intentionally excluded from the vault's HMAC, so editing them does not require re-signing. Review schema changes in code review; the integrity check does not protect those rules.

## Command reference

| Command | Purpose |
| --- | --- |
| `ramenv menu` | List available ingredients. |
| `ramenv init [--ingredient <ingredient>]` | Initialize a workspace and vault in the current directory. |
| `ramenv init workspace [--ingredient <ingredient>]` | Initialize workspace metadata and keys without a root vault. |
| `ramenv init service` | Register and initialize a vault in an existing workspace. |
| `ramenv onboard <env>` | Import the current directory's `.env`; choose which values to encrypt. |
| `ramenv create-env <env>` | Create a shared environment key and an empty environment in the current vault. |
| `ramenv set <env> <key> [--plaintext]` | Interactively add or update a value; encrypted by default. |
| `ramenv delete <env> <key>` | Delete a variable from the selected environment. |
| `ramenv list <env> [--reveal]` | Display values, masked by default. |
| `ramenv validate [<env>]` | Validate one or all environments in the current vault. |
| `ramenv diff <env1> <env2> [--reveal]` | Compare two environments in the current vault, masking values by default. |
| `ramenv run <env> -- <command> [args...]` | Decrypt and inject values, then execute a program. |
| `ramenv rotate <env> [--yes]` | Rotate the shared encryption key and re-encrypt affected workspace vaults. |
| `ramenv remove-env <env> [--yes]` | Remove an environment from affected workspace vaults and delete its key. |

Use `ramenv <command> --help` for command-specific options.

## Security and key handling

### Local keys

The default `local` ingredient writes unencrypted key material to `.ramenv.keys` at the workspace root. Treat that file as a secret:

- Keep it out of Git and restrict access using your operating system's file permissions.
- Back it up securely alongside the corresponding vault versions. Losing the encryption key makes encrypted values unrecoverable.
- Share it only through a secure channel with trusted collaborators or deployment systems that need it.
- Prefer a cloud ingredient when you need identity-based access instead of distributing a local key file.

Initialization adds ignore entries, but `.gitignore` does not untrack files already committed. Check your Git history and rotate any keys or credentials that have been exposed.

### What the protection covers

AES-256-GCM protects encrypted values. The HMAC authenticates the canonical environment data, including environment names, variable names, and stored values. ramenv verifies it before loading a vault. Use CLI commands to change environment data; manual edits will fail the integrity check.

The HMAC does not cover validation rules, workspace metadata, or cloud key-reference files. It uses shared-key authentication rather than a public-key signature. Anyone with the signing key can produce a valid HMAC.

In-memory injection avoids writing a decrypted `.env` file. It does not guarantee zero disk exposure or process isolation. Local keys remain on disk, onboarding leaves its input file intact, and applications receive secrets in their process environment. Your OS, application, debugger, logs, crash dumps, or other processes with sufficient access may expose them. Local keys and the vault in the same readable workspace do not protect secrets from an agent that can access both.

`list` and `diff` mask values by default, but masking may show portions of a value. `--reveal` prints complete decrypted values. Avoid these commands in shared logs, and use `--plaintext` only for configuration you are comfortable exposing in the repository.

## Contributing

Issues and pull requests are welcome. Include reproduction steps for bugs and tests for behavior changes. Never include real credentials, local key files, or decrypted secrets in an issue, patch, or test fixture.

From the ramenv source directory:

```sh
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets
```

The CLI implementation is in [`src/`](src/), integration tests are in [`tests/`](tests/), and cloud authentication guides are in [`docs/`](docs/).

## License

ramenv is licensed under the [MIT License](LICENSE).
