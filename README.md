# <img src="./logo.svg" width="28" height="28" align="top" alt="InferPing" /> inferping-probe

[![Release](https://img.shields.io/github/v/release/inferping/inferping-probe?color=0EA5E9&label=release)](https://github.com/inferping/inferping-probe/releases)
[![GHCR Container](https://img.shields.io/badge/ghcr.io-inferping%2Finferping--probe-38BDF8)](https://github.com/inferping/inferping-probe/pkgs/container/inferping-probe)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-34D399)](./LICENSE)

Lightweight, zero-dependency, zero-custody internal AI, LLM & Model Context Protocol (`MCP`) synthetic monitoring probe written in pure Go. Runs inside private Kubernetes clusters, GPU VPC subnets, Docker hosts, or corporate LANs and pushes 1-token streaming LLM Time-to-First-Token (`TTFT`), Inter-Token Latency (`ITL`), rate-limit headroom, MCP Streamable HTTP (`2025-03-26`) `tools/list` schema drift, and MCP auth-gate lock checks outbound via standard **OpenTelemetry (`OTLP/HTTP`)**.

Built for **[InferPing](https://inferping.eu)** (10-second European AI gateway, LLM edge latency, and MCP server security watchpost, 100% hosted in the EU) and compatible with **[OTelPing](https://otelping.eu)** and any standard OpenTelemetry Collector (`/v1/metrics`).

## Why `inferping-probe`?

- **Zero API key custody**: Your `LLM_API_KEY` or `MCP_BEARER_TOKEN` stays 100% inside your own VPC or Kubernetes Secret (`auth_env`). Only compact numeric OpenTelemetry gauges (`inferping.llm.ttft_ms`, `inferping.ratelimit.remaining_tokens`, `inferping.mcp.tools_count`) are pushed outbound to `https://app.inferping.eu/v1/metrics`.
- **Zero inbound firewall ports**: Connects strictly outbound over HTTPS (`443`).
- **Zero third-party Go dependencies**: Pure Go standard library (`CGO_ENABLED=0`), auditable in minutes, ~6 MB static binary, distroless non-root container (`< 25 MiB` RAM).
- **5 Check Modes**:
  1. **`llm`**: Sends a 1-token streaming chat completion canary (`max_tokens: 1, stream: true`), measures real SSE Time-to-First-Token (`TTFT`) and Inter-Token Latency (`ITL`) across standard `content`, `reasoning_content`, and `tool_calls` deltas, and extracts remaining token/request headroom from `x-ratelimit-*` and `anthropic-ratelimit-*` headers.
  2. **`mcp`**: Executes the full **MCP `2025-03-26` Streamable HTTP** lifecycle (`POST initialize` -> `Mcp-Session-Id` -> `notifications/initialized` -> `tools/list` -> `DELETE` session teardown), verifies minimum tool count (`expect_tools`), and computes a canonical 16-hex SHA-256 fingerprint over tool names and `inputSchema` (`expect_schema_hash`) to alert on silent tool drift or rug-pulls.
  3. **`mcp-gate`**: Sends an unauthenticated JSON-RPC 2.0 `initialize` request and passes only when the MCP server properly rejects unauthenticated callers (`HTTP 401`, `403`, `404`, or `405`). Alerts immediately if an MCP server ever responds `200 OK` without authentication.
  4. **`http`**: Standard HTTP/HTTPS endpoint check with W3C `traceparent`, DNS/TCP/TLS/TTFB breakdown, X.509 certificate expiry tracking, and custom internal CA support (`tls_ca_file`).
  5. **`tcp` / `dns`**: Raw TCP/TLS port checks (for internal Qdrant, Milvus, Redis, PostgreSQL) and split-horizon DNS checks.

## Quickstart (Zero Config File)

Grab your workspace API key (`inf_live_...`) from **[app.inferping.eu](https://app.inferping.eu)** and run:

```bash
export INFERPING_API_KEY="inf_live_your_workspace_key"
export INFERPING_REGION="k8s-gpu-eu"
export LLM_API_KEY="sk-your-local-vllm-or-mistral-key"
export INFERPING_TARGETS="vLLM-Internal=llm://https://vllm.internal:8443/v1/chat/completions,Public-MCP-Gate=mcp-gate://https://mcp.company.eu/mcp"

go run github.com/inferping/inferping-probe/cmd/inferping-probe@latest
```

 Or run the multi-arch distroless container from GitHub Container Registry:

```bash
docker run -d --name inferping-probe --restart unless-stopped \
  -e INFERPING_API_KEY="inf_live_your_workspace_key" \
  -e INFERPING_REGION="docker-gpu-eu" \
  -e LLM_API_KEY="sk-..." \
  -v $(pwd)/inferping.yaml:/etc/inferping/inferping.yaml:ro \
  ghcr.io/inferping/inferping-probe:latest --config /etc/inferping/inferping.yaml
```

Run once for CI/CD pipelines or Kubernetes CronJobs:

```bash
inferping-probe --config inferping.yaml --once
```

## Configuration (`inferping.yaml`)

Copy [`inferping.example.yaml`](./inferping.example.yaml) to `inferping.yaml`:

```yaml
endpoint: "https://app.inferping.eu"
api_key: "${INFERPING_API_KEY}"
region: "vpc-gpu-eu-01"
interval: "60s"

checks:
  - name: "Internal vLLM Inference Cluster"
    group: "Sovereign-AI-Backends"
    kind: "llm"
    target: "https://vllm.internal.company.eu/v1/chat/completions"
    model: "mistral-small-latest"
    auth_env: "LLM_API_KEY"
    timeout: "15s"
    tls_ca_file: "/etc/inferping/internal-ca.pem"

  - name: "Internal Customer-Support MCP Server"
    group: "Internal-MCP-Agents"
    kind: "mcp"
    target: "https://mcp.internal.company.eu/mcp"
    auth_env: "MCP_BEARER_TOKEN"
    expect_tools: 3
    expect_schema_hash: "8f3a1c90e4b27d11"
    timeout: "10s"

  - name: "Public MCP Reverse-Proxy Auth Gate"
    group: "External-Gates"
    kind: "mcp-gate"
    target: "https://mcp.company.eu/mcp"
    interval: "30s"
```

## Deployment

- **Docker Compose**: [`docker-compose.yml`](./docker-compose.yml) (`docker compose up -d`)
- **Kubernetes**: [`deploy/k8s/deployment.yaml`](./deploy/k8s/deployment.yaml)
- **Linux systemd**: [`deploy/systemd/inferping-probe.service`](./deploy/systemd/inferping-probe.service)

## Exported OpenTelemetry Metrics (`OTLP/HTTP`)

Each check emits a `ResourceMetrics` entry (`service.name`, `service.group`, `probe.region`, `check.kind`, `url.full`, `trace.id`, `mcp.schema.sha256`) containing:

| Metric | Type | Unit | Description |
| :--- | :--- | :--- | :--- |
| `check.passed` | Gauge (Int) | `1` | `1` when healthy, `0` when failed |
| `http.client.duration` | Gauge (Double) | `ms` | End-to-end check duration |
| `http.response.status_code` | Gauge (Int) | `1` | HTTP status code |
| `inferping.llm.ttft_ms` | Gauge (Double) | `ms` | Streaming LLM Time-to-First-Token (or MCP `initialize` latency) |
| `inferping.llm.itl_ms` | Gauge (Double) | `ms` | Streaming LLM Inter-Token Latency |
| `inferping.ratelimit.remaining_tokens` | Gauge (Int) | `1` | Remaining token quota reported by upstream AI gateway headers |
| `inferping.mcp.tools_count` | Gauge (Int) | `1` | Number of tools returned by MCP `tools/list` |
| `net.dns.duration` | Gauge (Double) | `ms` | DNS lookup latency |
| `net.tls.duration` | Gauge (Double) | `ms` | TLS handshake latency |
| `http.ttfb.duration` | Gauge (Double) | `ms` | Time to first response byte |
| `tls.cert.days_remaining` | Gauge (Int) | `d` | Days until leaf X.509 certificate expires |

## Related European Platforms

- **[InferPing (`inferping.eu`)](https://inferping.eu)**: 10-second European AI gateway, LLM edge latency, and `#mcp-gate` security monitoring (`EUR 39/mo`).
- **[OTelPing (`otelping.eu`)](https://otelping.eu)** & **[`otelping-probe`](https://github.com/otelping/otelping-probe)**: 10-second European web, load-balancer, DNS, and cron uptime monitoring with native OpenTelemetry (`EUR 39/mo`).
- **[Vallocor (`vallocor.eu`)](https://vallocor.eu)**: Independent European cybersecurity watchpost (`Outpost` / `Sentinel` / `Bastion`) and on-site `Vallocor Pulse` sensor alongside SMEs and their IT partners.

## License

Apache License 2.0 - Built in the Netherlands (EU) by **[InferPing](https://inferping.eu)** (Vallocor Security Engineering / GREYPIXEL ICT).
