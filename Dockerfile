# syntax=docker/dockerfile:1

# --- build stage ---
FROM golang:1.26.9-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
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
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/pstonn /app
COPY --from=build --chown=65532:65532 /data /data
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app"]
