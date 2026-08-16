# syntax=docker/dockerfile:1

# --- build stage ---
FROM golang:1.25.13-alpine@sha256:844b27705f54e73773e0f9bc3c780633b9d7f4b4831bf35cdad02a81a4c80bd0 AS build
WORKDIR /src

# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Pure-Go, statically linked, stripped.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pstonn .

# Pre-create the data dir owned by the nonroot uid. When an empty named volume
# is mounted here, Docker copies this ownership onto it, so the service can
# write its SQLite file without running as root.
RUN mkdir -p /data && chown 65532:65532 /data

# --- runtime stage ---
# distroless/static: no shell, includes CA certs for the council and SMTP TLS
# calls, runs as nonroot. The binary self-probes via `-healthcheck`, no curl.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
COPY --from=build /out/pstonn /app
COPY --from=build --chown=65532:65532 /data /data
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app"]
