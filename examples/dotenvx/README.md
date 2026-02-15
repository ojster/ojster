## Ojster with Dotenvx Example

Run these commands from the repo root directory to swap the default Ojster encryption backend with Dotenvx. See [compose.dotenvx.yaml](./compose.dotenvx.yaml) for the updated Compose values.

```sh
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
docker compose -f compose.yaml -f examples/dotenvx/compose.dotenvx.yaml up -d
# See that the app has access to decrypted env vars
docker logs -f ojster_example_client
# Cleanup
docker compose down
```