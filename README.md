# Ojster – GitOps-safe one-way encrypted secrets for Docker Compose.

**Problem:** I can manage my entire Docker Compose stack with Git, _except secrets_.

**Solution:** Encrypt your secrets using Ojster and safely store them in Git — even inside a public repository. Values can only be decrypted by the server holding the private key.

<p align="center"><img width="115" height="115" alt="Ojster Logo" src="https://avatars.githubusercontent.com/u/257382693" /></p>

Docker Compose workflows commonly rely on environment variables. Even when encrypted with tools like [Ansible Vault](https://docs.ansible.com/projects/ansible/latest/cli/ansible-vault.html), [Dotenvx](https://github.com/dotenvx/dotenvx), or [env-vault](https://github.com/romantomjak/env-vault), decrypted values often end up embedded in container specs, visible in management UIs (Docker Desktop, Portainer), or leaked via `docker inspect`, logs, or image metadata.

**Ojster** closes this gap. It is a companion to Dotenvx that enables **zero-trust, ephemeral secrets for Docker Compose**, ideal for self-hosting prebuilt images in a GitOps workflow. Decryption happens _just in time_ during container startup and remains exclusively in memory under strict least-privilege constraints.

## Benefits

- **Securely store secrets next to Compose files** — encrypted values are safe to commit to Git.
- **No plaintext secrets in container specs** — decrypted values exist only in RAM.
- **Minimal integration effort** — no need to override entrypoints or commands.
- **Encrypt new secrets without private key access** — anyone can encrypt; only the server can decrypt.
- **Air-gapped, least-privileged server** — no internet, no DNS, immutable rootfs, tmpfs, non-root user, zero capabilities.
- **Auditable and lightweight** — ~500 lines of Go (compiled by you), no third-party runtime dependencies on the client.

Get ready to BYOB and safely store encrypted secrets in Git.

## 🚧 Project status: early stages

Ojster is in an early-stage, pre-release phase. Expect breaking changes as the design evolves, security hardening improves, and real-world feedback shapes the API and integration model. The core concepts are stable, but details may change between versions. Review release notes before upgrading.

## Quick start

On the server that hosts your Docker containers:

```sh
git clone https://github.com/ojster/ojster
cd ojster

# Add some env vars
echo EXAMPLE1=1234 > .env
echo EXAMPLE2=HelloWorld >> .env

# Encrypt env vars with the dotenvx CLI in a locked-down container
docker run -it --rm -v $(pwd):/app --workdir=/app --pull=always \
  -u=64646:64646 --cap-drop=ALL --network=none \
  --security-opt=no-new-privileges=true dotenv/dotenvx encrypt

# Verify encrypted and safe to store in Git
cat .env

# Build Your Own Binary
docker bake

# Bring up example stack
docker compose up -d
# See that the app has access to decrypted env vars
docker logs -f ojster_example_client
# Cleanup
docker compose down
```

## Integrating existing stacks

Add the 7-line snippet (marked **OJSTER INTEGRATION** in [compose.yaml](./compose.yaml)) to any service you want to integrate. Ojster acts as a lightweight `docker-init` replacement and injects decrypted values at process start — no need to modify entrypoints, commands, or rebuild images.

## Comparison

### Bitnami Sealed Secrets

If you’re familiar with Kubernetes, **Ojster is the closest conceptual match to Bitnami Sealed Secrets — but for Docker Compose**.

Shared principles:

- **Encrypted secrets stored safely in Git**
- **One-way encryption** — anyone can encrypt; only the system holding the private key can decrypt
- **Plaintext never appears in configuration files**

Sealed Secrets uses a Kubernetes controller. Ojster applies the same pattern to Docker Compose using a lightweight client and a hardened decryption server.

### Dotenvx and Docker secrets

Ojster encryption is currently “powered by” [Dotenvx](https://dotenvx.com), but the projects are not officially affiliated. See [Dotenvx docs](https://dotenvx.com/docs/) for usage instructions. The table below compares Ojster to plain Dotenvx and Docker secrets.

| Feature                                                 | Ojster | `dotenvx run`<br>outside container | `dotenvx run`<br>inside container | Docker secrets |
| ------------------------------------------------------- | -----: | ---------------------------------: | --------------------------------: | -------------: |
| **Secure secrets in Git**                               |     ✅ |                                 ✅ |                                ✅ |             ❌ |
| **Encrypted env vars<br>in container spec**             |     ✅ |                                 ❌ |                                ⚠️ |             ❌ |
| **Unmodified<br>container image**                       |     ✅ |                                 ✅ |                                ❌ |             ✅ |
| **Native Docker Compose**                               |     ✅ |                                 ❌ |                                ✅ |             ✅ |
| **Air-gapped<br>private key access**                    |     ✅ |                                 ❌ |                                ❌ |            N/A |
| **0 third-party runtime<br>dependencies (client side)** |     ✅ |                                 ✅ |                                ❌ |             ✅ |
| **Image size increase**                                 |    N/A |                                N/A |                            ~50 MB |            N/A |

**Interpretation**

- **Ojster** integrates encrypted secrets into GitOps Compose workflows with minimal attack surface.
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

### High-level flow

1. **Client selection:** scan environment for values matching `OJSTER_REGEX` (configurable).
2. **POST to server:** send `key → encrypted value` map.
3. **Server workdir:** create a tmpfs directory, write `.env`, symlink `.env.keys`.
4. **Subprocess:** run `dotenvx get -o` (configurable) to decrypt in memory.
5. **Validation:** ensure subprocess returns only requested keys.
6. **Return:** send decrypted map back to client.
7. **Exec:** client merges values and `exec`s the real entrypoint.

### Key implementation details

- **Tmpfs enforcement** using Linux `statfs`
- **Strict validation** of subprocess output
- **Minimal logging** to avoid leaking secrets
- **Configurable regex** to detect encrypted values

## Security considerations

Securely provision the private key on the Ojster server host. Only the Ojster server should ever have access to the private key.

### Recommendations

- Protect the private key both at rest (encrypted storage or HSM/TPM) and in transit.
- Enforce strict private key file permissions: `chmod 600` and ownership matching UID/GID running the Ojster server.
- Rotate keys if compromised; re-encrypt secrets as needed.
- Use `internal: true` Docker networks; isolate each client/server pair.
- Keep server container hardened: non-root, drop capabilities, set `no-new-privileges`, no DNS, no outbound network access, immutable rootfs, tmpfs for tmp files.

## Contributing and license

**Contributing**

- Open issues for bugs or feature requests.
- Ensure `./test.sh` passes.
- Keep changes small and security-aware.
- No third-party runtime dependencies will be accepted.

**Testing**

```sh
export BUILDKIT_PROGRESS=plain
docker bake test # logs in ./log/test.log
```

**License**

Apache License 2.0.

## Why Ojster?

Ojster (pronounced “oyster”) is a metaphor for a protective shell that keeps something valuable sealed away until the moment it’s needed. The J gives the name a distinctive, memorable twist while subtly nodding to its creator. Its nautical undertone fits naturally within the Docker ecosystem.
