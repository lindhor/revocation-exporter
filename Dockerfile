# Static build, distroless runtime: one binary, no shell, runs as nonroot.
FROM docker.io/library/golang:1.27.3 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" -o /revocation-exporter .

# Pinned by digest (2026-11-08): distroless publishes no version tags, and a
# floating tag would make two builds of one commit differ.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /revocation-exporter /revocation-exporter
USER nonroot
EXPOSE 10999
ENTRYPOINT ["/revocation-exporter"]
CMD ["-config", "/etc/revocation-exporter/config.yaml"]
