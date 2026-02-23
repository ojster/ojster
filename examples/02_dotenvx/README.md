## Ojster Dotenvx integration example

Run these commands from the repo root directory to swap the default Ojster encryption backend with Dotenvx. See [compose.dotenvx.yaml](./compose.dotenvx.yaml) for the updated Compose values.

```sh
# Add some env var
echo EXAMPLE=1234 > .env

# Encrypt env vars with the dotenvx CLI in a locked-down container
docker run -it --rm -v $(pwd):/app --workdir=/app --pull=always \
  -u=64646:64646 --cap-drop=ALL --network=none \
  --security-opt=no-new-privileges=true dotenv/dotenvx encrypt

# Verify encrypted and safe to store in Git
cat .env

# Build Your Own Binary (image)
docker bake

# Bring up Ojster server
docker compose -f compose.yaml -f examples/02_dotenvx/compose.dotenvx.yaml up -d

# Bring up example stack Ojster enabled and regex overridden for dotenvx compatibility
OJSTER_REGEX="^'?(encrypted:[A-Za-z0-9+/=]+)'?$" docker compose -f ./examples/01_client/compose.base.yaml -f ./examples/01_client/compose.ojster.yaml -p ojster-client-example --project-directory=. up

# Note that the app has access to decrypted env vars

# Cleanup
docker compose -p ojster-client-example down
docker compose down -v
```