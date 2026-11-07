# Static build, distroless runtime: one binary, no shell, runs as nonroot.
FROM docker.io/library/golang:1.27 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" -o /revocation-exporter .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /revocation-exporter /revocation-exporter
USER nonroot
EXPOSE 9793
ENTRYPOINT ["/revocation-exporter"]
CMD ["-config", "/etc/revocation-exporter/config.yaml"]
