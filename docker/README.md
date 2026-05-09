# docker/

Multi-stage Dockerfiles for both reference-client implementations.

## Files

- **`go.Dockerfile`**: Go impl. `golang:1.26-alpine` build stage,
  `alpine:3.21` runtime. CGO disabled (pure-Go SQLite via
  `modernc.org/sqlite`). Output binary at `/usr/local/bin/semp-client`.
- **`ts.Dockerfile`**: TypeScript impl. `node:22-alpine` build and
  runtime stages. Build stage installs `python3 make g++` for
  `better-sqlite3`'s native compile; runtime stage drops them via
  stage separation. Entrypoint: `node /app/dist/cli.js`.
- **`docker-compose.yml`**: orchestrates either impl via
  `COMPOSE_PROFILES=go` or `COMPOSE_PROFILES=ts`.

## Build

    docker build -f docker/go.Dockerfile -t semp-client:go .
    docker build -f docker/ts.Dockerfile -t semp-client:ts .

(Run from the repo root so the Dockerfile can `COPY impl/go`,
`COPY impl/ts`, and `COPY shared`.)

## Run

    docker run --rm -v ./alice.toml:/etc/semp/semp.toml:ro semp-client:go status
    docker run --rm -v ./alice.toml:/etc/semp/semp.toml:ro semp-client:ts status

## Compose

Place per-user TOML files under `docker/fixtures/` (untracked), then:

    COMPOSE_PROFILES=go docker compose -f docker/docker-compose.yml run semp-client-go
    COMPOSE_PROFILES=ts docker compose -f docker/docker-compose.yml run semp-client-ts

The default with no profile is "nothing starts", which forces an
explicit choice. Mounting the fixtures directory read-only at
`/etc/semp` keeps secrets out of the image layers.
