# SECURITY.md - inferping-probe Security Architecture & Review Log

## 1. Security Controls

- **Zero API Key Custody**: `LLM_API_KEY` and `MCP_BEARER_TOKEN` stay strictly inside the customer's VPC or Kubernetes Secret (`auth_env`) and are never transmitted in OTLP metric exports.
- **Zero Third-Party Dependencies**: Pure Go standard library (`CGO_ENABLED=0`), packaged on `gcr.io/distroless/static-debian12:nonroot` (`uid=65532`).
- **Role Separation from Corporate DNS/SIEM Infrastructure**: Passive DNS/firewall/SIEM Shadow-AI domain counting is isolated in [`inferping/inferping-dns-collector`](https://github.com/inferping/inferping-dns-collector) so corporate AD, firewall, and log-platform hosts never run active endpoint/MCP probing code.

## 2. Commit Security Notes

- **2026-11-25 (`v1.1.0`)**: Separated passive DNS/syslog Shadow-AI counting out into the dedicated [`inferping/inferping-dns-collector`](https://github.com/inferping/inferping-dns-collector) repository so `inferping-probe` remains strictly focused on private VPC LLM `TTFT` and `MCP` synthetic checks.
