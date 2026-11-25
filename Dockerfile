# syntax=docker/dockerfile:1
# Build from the repository root:  docker build -t notes-syncd .
#
# The result is a distroless image: the server binary, the built web app, CA
# certificates and nothing else (no shell, no package manager), running as an
# unprivileged user.

# --- Web app, part 1: the shared core compiled to WebAssembly ---------------
# The web app is the same for every CPU architecture, so these two stages run
# natively on the build machine even when the image is for another one.
FROM --platform=$BUILDPLATFORM rust:1.97-slim-bookworm AS wasm
RUN rustup target add wasm32-unknown-unknown \
    && cargo install wasm-bindgen-cli --version 0.2.130 --locked
WORKDIR /src
COPY common/core common/core
COPY client/web/wasm client/web/wasm
RUN cargo build --manifest-path client/web/wasm/Cargo.toml --release --locked \
        --target wasm32-unknown-unknown \
    && wasm-bindgen --target web --out-dir /pkg \
        client/web/wasm/target/wasm32-unknown-unknown/release/notes_web.wasm

# --- Web app, part 2: TypeScript and bundling --------------------------------
FROM --platform=$BUILDPLATFORM node:26-bookworm-slim AS web
WORKDIR /web
COPY client/web/package.json client/web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY client/web/ ./
COPY --from=wasm /pkg src/pkg
RUN npx tsc --noEmit && npx vite build

# --- Server -------------------------------------------------------------------
FROM rust:1.97-slim-bookworm AS server
WORKDIR /src/server
# The server's tests use the core; cargo wants to see it even when not testing.
COPY common/core /src/common/core
# Compile the dependencies in their own layer, so that a change to the source
# does not rebuild all of them.
COPY server/Cargo.toml server/Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && touch src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src
COPY server/src ./src
# Touching makes sure cargo sees the real sources as newer than the stand-ins.
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.title="notes-syncd" \
      org.opencontainers.image.description="End-to-end encrypted notes: sync server and web app" \
      org.opencontainers.image.source="https://github.com/SetZero/notes-app"
COPY --from=server /src/server/target/release/notes-syncd /usr/local/bin/notes-syncd
# Set server.static_dir = "/usr/share/notes-web" to serve it at /app/.
COPY --from=web /web/dist /usr/share/notes-web
USER 65532:65532
VOLUME /data
EXPOSE 8080
ENV NOTES_SYNCD_CONFIG=/etc/notes-syncd/config.toml
ENTRYPOINT ["/usr/local/bin/notes-syncd"]
