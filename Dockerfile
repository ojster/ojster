# ============================================
# 1. Setup builder
# ============================================
FROM golang AS builder

ARG UID=64646
ARG GID=64646

ENV CGO_ENABLED=0 GOOS=linux GOARCH=arm64 HOME=/app

USER $UID:$GID
WORKDIR /app

COPY ojster.go .

# Compute version with .git and version.sh mounted
RUN --network=none --mount=type=bind,source=.git,target=/app/.git \
    --mount=type=bind,source=version.sh,target=/app/version.sh <<EOF
    set -o pipefail
    git config --global --add safe.directory /app
    ./version.sh | tee vers
EOF

# Create a module
RUN --network=none go mod init ojster

# ============================================
# 2. Dedicated test stage (skipped by default)
# ============================================
FROM builder AS test

# Add dotenvx, required by tests
COPY --from=dotenv/dotenvx  \
    /usr/local/bin/dotenvx /usr/local/bin/dotenvx

# Add the tests
COPY ojster_test.go .

WORKDIR /tmp2
WORKDIR /app

# Run tests with a meaningful version string
RUN --network=none --mount=type=tmpfs,target=/tmp <<EOF
    set -o pipefail
    mkdir output
    go test ./... -v -coverprofile=output/coverage.out \
        -ldflags="-X main.version=$(cat vers)" \
        | tee output/test.log
    go tool cover -html=output/coverage.out -o output/coverage.html
    rm output/coverage.out
EOF

# ============================================
# 3. Output test log only (skipped by default)
# ============================================
FROM scratch AS test-scratch
COPY --from=test /app/output .

# ============================================
# 4. Dedicated static binary build stage
# ============================================
FROM builder AS binary

# Build with injected version
RUN --network=none go build \
    -ldflags="-s -w -extldflags '-static' -X main.version=$(cat vers)" \
    -o ojster .

# ============================================
# 5. Output ojster binary only (default)
# ============================================
FROM scratch AS binary-scratch
COPY --from=binary /app/ojster /ojster
