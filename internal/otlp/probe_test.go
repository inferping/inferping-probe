package otlp_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferping/inferping-probe/internal/checker"
	"github.com/inferping/inferping-probe/internal/config"
	"github.com/inferping/inferping-probe/internal/otlp"
)

func TestEndToEndLLMAndMCPChecksAndOTLPExport(t *testing.T) {
	ctx := context.Background()

	// 1. Mock streaming LLM endpoint (SSE with token delta + rate-limit header)
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk-local-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("x-ratelimit-remaining-tokens", "48500")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"pong\"}}]}\n\ndata: [DONE]\n\n"))
	}))
	defer llmSrv.Close()

	// 2. Mock MCP Streamable HTTP (2025-03-26) endpoint
	mcpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		body, _ := io.ReadAll(r.Body)
		s := string(body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(s, `"initialize"`) {
			w.Header().Set("Mcp-Session-Id", "sess-eu-123")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`))
			return
		}
		if strings.Contains(s, `"tools/list"`) {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"search_docs","inputSchema":{"type":"object"}}]}}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer mcpSrv.Close()

	// 3. Mock public MCP Auth-Gate endpoint (properly returns 401 Unauthorized)
	gateSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer gateSrv.Close()

	// 4. Mock OTLP/HTTP collector endpoint
	var gotAuth, gotEncoding string
	var gotBody []byte
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotEncoding = r.Header.Get("Content-Encoding")
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		defer gz.Close()
		gotBody, _ = io.ReadAll(gz)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer collector.Close()

	t.Setenv("TEST_INFERPING_KEY", "inf_live_test_secret_123")
	t.Setenv("LLM_API_KEY", "sk-local-secret")

	yamlFile := filepath.Join(t.TempDir(), "inferping.yaml")
	yamlContent := `endpoint: "` + collector.URL + `"
api_key: "${TEST_INFERPING_KEY}"
region: "vpc-gpu-eu-west"
interval: "30s"

checks:
  - name: "Internal vLLM Cluster"
    group: "Sovereign-AI"
    kind: "llm"
    target: "` + llmSrv.URL + `/v1/chat/completions"
    model: "mistral-small-latest"
    auth_env: "LLM_API_KEY"
  - name: "Internal MCP Agent"
    group: "MCP-Fleet"
    kind: "mcp"
    target: "` + mcpSrv.URL + `/mcp"
    expect_tools: 1
  - name: "External MCP Gate"
    group: "MCP-Fleet"
    kind: "mcp-gate"
    target: "` + gateSrv.URL + `/mcp"
`
	if err := os.WriteFile(yamlFile, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	cfg, err := config.Load(yamlFile)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if cfg.APIKey != "inf_live_test_secret_123" || len(cfg.Checks) != 3 {
		t.Fatalf("unexpected parsed config: %+v", cfg)
	}

	var results []checker.Result
	for _, c := range cfg.Checks {
		r := checker.Run(ctx, c)
		if !r.Passed {
			t.Fatalf("expected check %q (%s) to pass, got err=%q status=%d", c.Name, c.Kind, r.ErrorMessage, r.StatusCode)
		}
		results = append(results, r)
	}
	if results[0].RemainingTokens != 48500 {
		t.Fatalf("expected remaining tokens 48500, got %d", results[0].RemainingTokens)
	}
	if results[1].MCPToolsCount != 1 || results[1].MCPSchemaHash == "" {
		t.Fatalf("expected 1 MCP tool and non-empty schema hash, got %+v", results[1])
	}

	exp := otlp.NewExporter(cfg.Endpoint, cfg.APIKey, cfg.Region, cfg.Headers)
	if err := exp.Export(ctx, results); err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if gotAuth != "Bearer inf_live_test_secret_123" || gotEncoding != "gzip" {
		t.Fatalf("unexpected OTLP headers: auth=%q encoding=%q", gotAuth, gotEncoding)
	}
	var parsed map[string]any
	if err := json.Unmarshal(gotBody, &parsed); err != nil {
		t.Fatalf("invalid OTLP JSON payload: %v", err)
	}
	bodyStr := string(gotBody)
	for _, want := range []string{"Internal vLLM Cluster", "Internal MCP Agent", "External MCP Gate", "inferping.llm.ttft_ms", "inferping.ratelimit.remaining_tokens", "inferping.mcp.tools_count", "mcp.schema.sha256"} {
		if !strings.Contains(bodyStr, want) {
			t.Fatalf("expected %q in exported OTLP JSON: %s", want, bodyStr)
		}
	}
}
