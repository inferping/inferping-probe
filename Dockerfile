FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=1.0.0
RUN CLEAN_VER="${VERSION#v}" && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${CLEAN_VER}" -o /out/inferping-probe ./cmd/inferping-probe

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/inferping/inferping-probe"
LABEL org.opencontainers.image.description="Lightweight zero-custody internal AI, LLM TTFT & MCP server synthetic monitoring probe for InferPing"
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /out/inferping-probe /usr/local/bin/inferping-probe
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/inferping-probe"]
