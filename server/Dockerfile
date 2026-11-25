# syntax=docker/dockerfile:1
# Build:  docker build -t notes-syncd server/
# The result is a distroless image: the server binary, CA certificates and
# nothing else (no shell, no package manager), running as an unprivileged user.

FROM rust:1.97-slim-bookworm AS build
WORKDIR /src

# Compile the dependencies in their own layer, so that a change to the source
# does not rebuild all of them.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && touch src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
# Touching makes sure cargo sees the real sources as newer than the stand-ins.
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.title="notes-syncd" \
      org.opencontainers.image.description="End-to-end encrypted notes sync server" \
      org.opencontainers.image.source="https://github.com/SetZero/notes-app"
COPY --from=build /src/target/release/notes-syncd /usr/local/bin/notes-syncd
USER 65532:65532
VOLUME /data
EXPOSE 8080
ENV NOTES_SYNCD_CONFIG=/etc/notes-syncd/config.toml
ENTRYPOINT ["/usr/local/bin/notes-syncd"]
