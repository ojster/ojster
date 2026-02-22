# [Ojster – GitOps-safe one-way encrypted secrets](https://github.com/ojster/ojster)

**Problem:** I can manage my entire Docker Compose stack with Git, _except secrets_.

**Solution:** Encrypt your secrets using Ojster and safely store them in Git — even inside a public repository. Values can only be decrypted by the server holding the private key.

<p align="center"><img width="115" height="115" alt="Ojster Logo" src="https://avatars.githubusercontent.com/u/257382693" /></p>

Docker Compose workflows commonly rely on environment variables. Even when encrypted with tools like [Ansible Vault](https://docs.ansible.com/projects/ansible/latest/cli/ansible-vault.html), [Dotenvx](https://github.com/dotenvx/dotenvx), or [env-vault](https://github.com/romantomjak/env-vault), decrypted values often end up embedded in container specs, visible in management UIs (Docker Desktop, Portainer), or leaked via `docker inspect`, logs, or image metadata.

**Ojster** closes this gap. It provides **one-way, quantum-safe encryption** (MLKEM + AES) and a hardened decryption server so you can commit encrypted values to Git and decrypt them _just in time_ at container startup — in memory and under strict least-privilege constraints. This **zero-trust, ephemeral secrets** solution is ideal for self-hosting prebuilt images in a GitOps workflow with Docker Compose.

## Highlights

- **Securely store secrets next to Compose files** — encrypted values are safe to commit.
- **No plaintext secrets in container specs** — decrypted values exist only in RAM.
- **Minimal integration effort** — no need to override entrypoints or commands.
- **Anyone can encrypt; only the server can decrypt** — public-key, one-way encryption.
- **Air-gapped, least-privileged server** — no internet, no DNS, immutable rootfs, tmpfs, non-root user, zero capabilities.
- **Auditable and lightweight** — small Go codebase (compiled by you), no third-party runtime dependencies on the client.
- **Pluggable architecture** — Ojster ships its own `seal`, `unseal`, and `keypair` implementations (MLKEM + AES) and can also use Dotenvx as an alternative backend if desired.

Get ready to BYOB and safely store encrypted secrets in Git.

## 🚧 Project status: early stages

Ojster is in an early-stage, pre-release phase. Expect breaking changes as the design evolves, security hardening improves, and real-world feedback shapes the API and integration model. The core concepts are stable, but details may change between versions. Review release notes before upgrading.

## Quick start

On the server that hosts your Docker containers:

```sh
git clone https://github.com/ojster/ojster
cd ojster

# Build Your Own Binary (image)
docker bake

# Run containers as the current uid/gid to grant access to the files in this repo
# Not required for Docker Desktop on macOS
# For a production setup it's recommended to use a dedicated server uid/gid
PUID="$(id -u)"; PGID="$(id -g)"
export PUID PGID

# Common docker run flags
COMMON=(
  --user="${PUID:-64646}:${PGID:-64646}"
  --pull=never
  --read-only
  --cap-drop=ALL
  --network=none
  --security-opt=no-new-privileges=true
)

# Generate a keypair using Ojster's built-in keypair command
docker run "${COMMON[@]}" --rm -v "$(pwd)":/o ojster/ojster keypair

# Do NOT commit the ojster_priv.key to Git!

# Bring up ojster server
docker compose up -d

# Encrypt a variable using Ojster's built-in seal command (no private key needed)
# Enter an example secret and press Ctrl-D (twice) when done.
docker run "${COMMON[@]}" -it --rm -v "$(pwd)":/o ojster/ojster seal EXAMPLE

CLIENT_DIR=examples/01_client

COMMON=(
  --project-name=ojster-client-example
  --file=./"$CLIENT_DIR"/compose.base.yaml
  --project-directory=.
)

# Bring up example stack WITHOUT Ojster enabled
docker compose "${COMMON[@]}" up

# Note in output that env var is still encrypted (prefix OJSTER-1:)

# Bring up example stack WITH Ojster enabled
docker compose "${COMMON[@]}" -f ./"$CLIENT_DIR"/compose.ojster.yaml up

# Note in output that env var is now decrypted

# Cleanup
docker compose "${COMMON[@]}" down
docker compose down -v
```

Ideally the Ojster server compose.yaml file becomes part of the stack you manage via GitOps, as well a the PUBLIC key, so you can easily add new encrypted environment variables.

**Notes**

- The examples above use the Ojster-provided `keypair` and `seal` commands. If you prefer, [Ojster can also interoperate with Dotenvx](./examples/02_dotenvx/) — it is pluggable and works with Dotenvx out of the box.

## Integrate your stack

Add the snippet in [compose.ojster.yaml](./examples/01_client/compose.ojster.yaml) to any service you want to integrate. Ojster acts as a lightweight `docker-init` replacement and injects decrypted values at process start — no need to modify entrypoints, commands, or rebuild images.

### Podman compatibility

Ojster currently does not support podman. The dockerfile relies on a [BuildKit feature](https://github.com/moby/moby/issues/36677#issuecomment-957357940) which [podman/buildah doesn't offer](https://github.com/containers/buildah/issues/2323). Additionally [podman doesn't support the bake .hcl files](https://github.com/containers/buildah/issues/4796), [volume.type=image](https://github.com/containers/podman/issues/26505) and has a different `--init` implementation: `/run/podman-init`. But most importantly podman will throw this error when trying to provide our own init binary in combination with `--init`: "Error response from daemon: container create: conflict with mount added by --init to "/run/podman-init": duplicate mount destination".

## Comparison

### Bitnami Sealed Secrets

If you know Kubernetes, **Ojster is conceptually similar to Bitnami Sealed Secrets — but for Docker Compose**.

Shared principles:

- **Encrypted secrets stored safely in Git**
- **One-way encryption** — anyone can encrypt; only the private-key holder can decrypt
- **Plaintext never appears in configuration files**

Sealed Secrets uses a Kubernetes controller. Ojster applies the same pattern to Docker Compose using a lightweight client and a hardened decryption server.

### Dotenvx and Docker secrets

Ojster implements its own MLKEM + AES sealing/unsealing and keypair generation, but it remains **pluggable** and compatible with Dotenvx. The table below compares Ojster to plain Dotenvx (the free, Open Source version) and Docker secrets.

| Feature                                                 | Ojster | `dotenvx run`<br>outside container | `dotenvx run`<br>inside container | Docker secrets |
| ------------------------------------------------------- | -----: | ---------------------------------: | --------------------------------: | -------------: |
| **Secure secrets in Git**                               |     ✅ |                                 ✅ |                                ✅ |             ❌ |
| **Encrypted env vars<br>in container spec**             |     ✅ |                                 ❌ |                                ⚠️ |             ❌ |
| **Quantum-safe encryption**                             |     ✅ |                                 ❌ |                                ❌ |             ❌ |
| **Unmodified<br>container image**                       |     ✅ |                                 ✅ |                                ❌ |             ✅ |
| **Native Docker Compose**                               |     ✅ |                                 ❌ |                                ✅ |             ✅ |
| **Air-gapped<br>private key access**                    |     ✅ |                                 ❌ |                                ❌ |            N/A |
| **0 third-party runtime<br>dependencies (client side)** |     ✅ |                                 ✅ |                                ❌ |             ✅ |
| **Image size increase**                                 |    N/A |                                N/A |                            ~50 MB |            N/A |

**Interpretation**

- **Ojster** integrates encrypted secrets into GitOps Compose workflows with minimal attack surface using post-quantum cryptography (PQC).
- **`dotenvx run` outside container** calling `docker compose up` still places decrypted values into container specs (visible to orchestration tooling), requires wrapping around Compose commands, and is not air-gapped (e.g. to prevent a malicious dependency from data exfiltration).
- **`dotenvx run` inside container** requires shipping decryption tooling in **each image** (823 third-party dependencies) and exposes keys to **all containers**, increasing attack surface and image size. The [official walkthrough](https://dotenvx.com/docs/platforms/docker-compose) sets the private key as plaintext env var in the container spec.
- **Docker secrets** are not encrypted and unsafe to store in Git.

### Secret platforms

Ojster does not provide the feature set of a full secrets platform. If that's what you need, consider:

- [vault-env](https://github.com/bank-vaults/vault-env)
- [envconsul](https://github.com/hashicorp/envconsul)
- [infisical run](https://infisical.com/docs/cli/commands/run)

## Technical design and workings

### Design goals

- **Zero trust** — clients never hold private keys.
- **Ephemeral secrets** — decrypted values never touch disk.
- **Minimal client impact** — original entrypoints and runtime environments remain unchanged.
- **Local IPC transport** — server without network stack.

### High-level flow

1. **Selection:** client scans environment for values matching `OJSTER_REGEX` (configurable).
2. **IPC:** client posts `key → encrypted value` map to the Ojster server over a Unix domain socket.
3. **Decryption:** server decrypts using private key or outsources decryption to a user defined subprocess.
4. **Return:** server sends decrypted map back to client.
5. **Exec:** client merges values into the environment and `exec`s the real entrypoint.

### Key implementation details

- **Configurable subprocess** runs in tmp directory containing encrypted `.env` and `.env.keys` symlinked to private key
- **Tmpfs enforcement** using Linux `statfs`
- **Strict validation** of subprocess output
- **Minimal logging** to avoid leaking secrets
- **Configurable regex** to detect encrypted values

## Security considerations

Securely provision the private key on the Ojster server host. Only the Ojster server should ever have access to the private key. Access to the ojster volume (which contains the IPC socket file) is equivalent to the ability to request decryptions: any process that can open the socket can talk HTTP to the server and obtain decrypted values. Treat the socket like a sensitive IPC endpoint.

### Recommendations

- Protect the private key both at rest (encrypted storage or HSM/TPM) and in transit.
- Enforce strict private key file permissions: `chmod 600` and ownership matching UID/GID running the Ojster server.
- Rotate keys if compromised; re-encrypt secrets as needed.
- Avoid sharing the IPC socket with untrusted containers or services.
- Keep server container hardened: non-root, drop capabilities, set `no-new-privileges`, no DNS, no outbound network access, immutable rootfs, tmpfs for tmp files.

## Contributing and license

**Contributing**

- Open issues for bugs or feature requests.
- Ensure `./tools/test` passes locally.
- Keep changes small and security-aware.
- No third-party runtime dependencies will be accepted.

**Testing**

```sh
./tools/test
```

**License**

Apache License 2.0.

## Why Ojster?

Ojster (pronounced “oyster”) is a metaphor for a protective shell that keeps something valuable sealed away until the moment it’s needed. The J gives the name a distinctive, memorable twist while subtly nodding to its creator. Its nautical undertone fits naturally within the Docker ecosystem.
