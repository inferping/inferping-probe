package checker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/inferping/inferping-probe/internal/config"
)

type Result struct {
	Name            string
	Group           string
	Kind            string
	Target          string
	TraceID         string
	Passed          bool
	StatusCode      int
	TotalMS         float64
	DNSMS           float64
	TCPMS           float64
	TLSMS           float64
	TTFBMS          float64
	TTFTMS          float64
	ITLMS           float64
	RemainingTokens int64
	MCPToolsCount   int
	MCPSchemaHash   string
	CertDaysLeft    int
	ErrorMessage    string
	CheckedAt       time.Time
}

func newW3CTraceParent() (traceID, header string) {
	var raw [24]byte
	_, _ = rand.Read(raw[:])
	raw[0] |= 0x01
	raw[16] |= 0x01
	tID := hex.EncodeToString(raw[0:16])
	sID := hex.EncodeToString(raw[16:24])
	return tID, "00-" + tID + "-" + sID + "-01"
}

func buildTLSConfig(c config.CheckConfig, serverName string) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: c.TLSSkipVerify,
	}
	if strings.TrimSpace(c.TLSCAFile) != "" {
		pemBytes, err := os.ReadFile(c.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read tls_ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no valid PEM certificates in %s", c.TLSCAFile)
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

func Run(ctx context.Context, c config.CheckConfig) Result {
	cctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	switch c.Kind {
	case "llm":
		return runLLMStreamCanary(cctx, c)
	case "mcp":
		return runMCPStreamableHTTP(cctx, c)
	case "mcp-gate":
		return runMCPAuthGate(cctx, c)
	case "tcp":
		return runTCP(cctx, c)
	case "dns":
		return runDNS(cctx, c)
	default:
		return runHTTP(cctx, c)
	}
}

func runLLMStreamCanary(ctx context.Context, c config.CheckConfig) Result {
	traceID, traceparent := newW3CTraceParent()
	res := Result{
		Name:            c.Name,
		Group:           c.Group,
		Kind:            "llm",
		Target:          c.Target,
		TraceID:         traceID,
		RemainingTokens: -1,
		MCPToolsCount:   -1,
		CertDaysLeft:    -1,
		CheckedAt:       time.Now().UTC(),
	}

	targetURL := c.Target
	if !strings.Contains(targetURL, "://") {
		targetURL = "https://" + targetURL
	}
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Host == "" {
		res.ErrorMessage = "invalid target URL"
		return res
	}
	tlsCfg, err := buildTLSConfig(c, parsed.Hostname())
	if err != nil {
		res.ErrorMessage = err.Error()
		return res
	}

	payload := map[string]any{
		"model":       c.Model,
		"messages":    []map[string]string{{"role": "user", "content": "ping"}},
		"max_tokens":  1,
		"temperature": 0,
		"stream":      true,
	}
	rawBody, _ := json.Marshal(payload)

	var dnsStart, dnsDone, tcpStart, tcpDone, tlsStart, tlsDone time.Time
	var peerCertExpiry time.Time

	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tlsCfg,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: c.Timeout,
		DialContext:         (&net.Dialer{Timeout: c.Timeout}).DialContext,
	}
	defer tr.CloseIdleConnections()

	ht := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart: func(_, _ string) {
			if tcpStart.IsZero() {
				tcpStart = time.Now()
			}
		},
		ConnectDone: func(_, _ string, err error) {
			if err == nil && tcpDone.IsZero() {
				tcpDone = time.Now()
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsDone = time.Now()
			if err == nil && len(state.PeerCertificates) > 0 {
				peerCertExpiry = state.PeerCertificates[0].NotAfter
			}
		},
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, ht), http.MethodPost, targetURL, bytes.NewReader(rawBody))
	if err != nil {
		res.ErrorMessage = err.Error()
		return res
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", "InferPing-Probe/1.0 (+https://github.com/inferping/inferping-probe)")
	req.Header.Set("traceparent", traceparent)
	if c.AuthEnv != "" {
		if bearer := strings.TrimSpace(os.Getenv(c.AuthEnv)); bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
	}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	client := &http.Client{Transport: tr, Timeout: c.Timeout}
	resp, err := client.Do(req)
	if !dnsStart.IsZero() && !dnsDone.IsZero() {
		res.DNSMS = durMS(dnsDone.Sub(dnsStart))
	}
	if !tcpStart.IsZero() && !tcpDone.IsZero() {
		res.TCPMS = durMS(tcpDone.Sub(tcpStart))
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		res.TLSMS = durMS(tlsDone.Sub(tlsStart))
	}
	if !peerCertExpiry.IsZero() {
		days := int(math.Floor(time.Until(peerCertExpiry).Hours() / 24.0))
		if days < 0 {
			days = 0
		}
		res.CertDaysLeft = days
	}
	if err != nil {
		res.TotalMS = durMS(time.Since(start))
		res.ErrorMessage = compactErr(err)
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	res.RemainingTokens = parseHeaderInt64(resp.Header, "x-ratelimit-remaining-tokens", "anthropic-ratelimit-tokens-remaining")

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		res.TotalMS = durMS(time.Since(start))
		if resp.StatusCode == 529 {
			res.ErrorMessage = "AI provider overloaded (HTTP 529 Overloaded)"
		} else if resp.StatusCode == http.StatusTooManyRequests {
			res.ErrorMessage = "AI rate limit exceeded (HTTP 429 Too Many Requests)"
		} else {
			res.ErrorMessage = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return res
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 64*1024))
	var firstTokenAt, prevTokenAt time.Time
	var itlSum float64
	var itlCount int

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			if data == "[DONE]" {
				break
			}
			continue
		}
		if strings.Contains(data, `"content"`) || strings.Contains(data, `"reasoning_content"`) || strings.Contains(data, `"tool_calls"`) || strings.Contains(data, `"delta"`) {
			now := time.Now()
			if firstTokenAt.IsZero() {
				firstTokenAt = now
				res.TTFTMS = durMS(firstTokenAt.Sub(start))
				res.TTFBMS = res.TTFTMS
			} else {
				itlSum += durMS(now.Sub(prevTokenAt))
				itlCount++
			}
			prevTokenAt = now
		}
	}

	res.TotalMS = durMS(time.Since(start))
	if !firstTokenAt.IsZero() {
		res.Passed = true
		if itlCount > 0 {
			res.ITLMS = math.Round((itlSum/float64(itlCount))*10) / 10
		}
	} else {
		res.ErrorMessage = "SSE stream closed before emitting any token delta"
	}
	return res
}

func runMCPStreamableHTTP(ctx context.Context, c config.CheckConfig) Result {
	traceID, traceparent := newW3CTraceParent()
	res := Result{
		Name:            c.Name,
		Group:           c.Group,
		Kind:            "mcp",
		Target:          c.Target,
		TraceID:         traceID,
		RemainingTokens: -1,
		MCPToolsCount:   -1,
		CertDaysLeft:    -1,
		CheckedAt:       time.Now().UTC(),
	}

	targetURL := c.Target
	if !strings.Contains(targetURL, "://") {
		targetURL = "https://" + targetURL
	}
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Host == "" {
		res.ErrorMessage = "invalid target URL"
		return res
	}
	tlsCfg, err := buildTLSConfig(c, parsed.Hostname())
	if err != nil {
		res.ErrorMessage = err.Error()
		return res
	}

	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tlsCfg,
		DisableKeepAlives:   false,
		TLSHandshakeTimeout: c.Timeout,
		DialContext:         (&net.Dialer{Timeout: c.Timeout}).DialContext,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: c.Timeout}

	bearer := ""
	if c.AuthEnv != "" {
		bearer = strings.TrimSpace(os.Getenv(c.AuthEnv))
	}

	doRPC := func(body string, sessionID string) (*http.Response, []byte, error) {
		req, rErr := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(body))
		if rErr != nil {
			return nil, nil, rErr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("User-Agent", "InferPing-Probe/1.0 (+https://github.com/inferping/inferping-probe)")
		req.Header.Set("traceparent", traceparent)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if sessionID != "" {
			req.Header.Set("Mcp-Session-Id", sessionID)
		}
		for k, v := range c.Headers {
			req.Header.Set(k, v)
		}
		resp, doErr := client.Do(req)
		if doErr != nil {
			return nil, nil, doErr
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		return resp, extractJSONFromSSEOrBody(raw), nil
	}

	start := time.Now()
	initPayload := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"InferPing-Probe","version":"1.0"}}}`
	resp1, _, err := doRPC(initPayload, "")
	res.TTFTMS = durMS(time.Since(start))
	res.TTFBMS = res.TTFTMS
	if err != nil {
		res.TotalMS = durMS(time.Since(start))
		res.ErrorMessage = "MCP initialize failed: " + compactErr(err)
		return res
	}
	res.StatusCode = resp1.StatusCode
	if resp1.TLS != nil && len(resp1.TLS.PeerCertificates) > 0 {
		days := int(math.Floor(time.Until(resp1.TLS.PeerCertificates[0].NotAfter).Hours() / 24.0))
		if days < 0 {
			days = 0
		}
		res.CertDaysLeft = days
	}
	if resp1.StatusCode < 200 || resp1.StatusCode >= 300 {
		res.TotalMS = durMS(time.Since(start))
		res.ErrorMessage = fmt.Sprintf("MCP initialize returned HTTP %d", resp1.StatusCode)
		return res
	}
	sessionID := strings.TrimSpace(resp1.Header.Get("Mcp-Session-Id"))

	_, _, _ = doRPC(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, sessionID)
	resp3, toolsJSON, err := doRPC(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, sessionID)

	if sessionID != "" {
		if delReq, dErr := http.NewRequestWithContext(ctx, http.MethodDelete, targetURL, nil); dErr == nil {
			delReq.Header.Set("Mcp-Session-Id", sessionID)
			if bearer != "" {
				delReq.Header.Set("Authorization", "Bearer "+bearer)
			}
			if delResp, doErr := client.Do(delReq); doErr == nil {
				delResp.Body.Close()
			}
		}
	}

	res.TotalMS = durMS(time.Since(start))
	if err != nil || resp3.StatusCode < 200 || resp3.StatusCode >= 300 {
		res.ErrorMessage = "MCP tools/list failed"
		return res
	}

	var rpcResp struct {
		Result struct {
			Tools []struct {
				Name        string          `json:"name"`
				InputSchema json.RawMessage `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if uErr := json.Unmarshal(toolsJSON, &rpcResp); uErr != nil {
		res.ErrorMessage = "invalid MCP tools/list JSON-RPC response"
		return res
	}

	res.MCPToolsCount = len(rpcResp.Result.Tools)
	canon := make([]string, 0, len(rpcResp.Result.Tools))
	for _, t := range rpcResp.Result.Tools {
		var compact bytes.Buffer
		if len(t.InputSchema) > 0 && json.Compact(&compact, t.InputSchema) == nil {
			canon = append(canon, t.Name+":"+compact.String())
		} else {
			canon = append(canon, t.Name+":{}")
		}
	}
	sort.Strings(canon)
	sum := sha256.Sum256([]byte(strings.Join(canon, "|")))
	res.MCPSchemaHash = hex.EncodeToString(sum[:8])

	minTools := c.ExpectTools
	if minTools > 0 && res.MCPToolsCount < minTools {
		res.ErrorMessage = fmt.Sprintf("MCP tools/list returned %d tools (expected >= %d)", res.MCPToolsCount, minTools)
		return res
	}
	if c.ExpectSchemaHash != "" && !strings.EqualFold(c.ExpectSchemaHash, res.MCPSchemaHash) {
		res.ErrorMessage = fmt.Sprintf("MCP tool schema drift: got %s, expected %s", res.MCPSchemaHash, c.ExpectSchemaHash)
		return res
	}

	res.Passed = true
	return res
}

func runMCPAuthGate(ctx context.Context, c config.CheckConfig) Result {
	traceID, traceparent := newW3CTraceParent()
	res := Result{
		Name:            c.Name,
		Group:           c.Group,
		Kind:            "mcp-gate",
		Target:          c.Target,
		TraceID:         traceID,
		RemainingTokens: -1,
		MCPToolsCount:   -1,
		CertDaysLeft:    -1,
		CheckedAt:       time.Now().UTC(),
	}

	targetURL := c.Target
	if !strings.Contains(targetURL, "://") {
		targetURL = "https://" + targetURL
	}
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Host == "" {
		res.ErrorMessage = "invalid target URL"
		return res
	}
	tlsCfg, err := buildTLSConfig(c, parsed.Hostname())
	if err != nil {
		res.ErrorMessage = err.Error()
		return res
	}

	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tlsCfg,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: c.Timeout,
		DialContext:         (&net.Dialer{Timeout: c.Timeout}).DialContext,
	}
	defer tr.CloseIdleConnections()

	initPayload := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"InferPing-MCP-Gate","version":"1.0"}}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(initPayload))
	if err != nil {
		res.ErrorMessage = err.Error()
		return res
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", "InferPing-Probe/1.0 (+https://github.com/inferping/inferping-probe)")
	req.Header.Set("traceparent", traceparent)

	start := time.Now()
	client := &http.Client{Transport: tr, Timeout: c.Timeout}
	resp, err := client.Do(req)
	res.TotalMS = durMS(time.Since(start))
	res.TTFTMS = res.TotalMS
	res.TTFBMS = res.TotalMS
	if err != nil {
		res.ErrorMessage = compactErr(err)
		return res
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))

	res.StatusCode = resp.StatusCode
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		days := int(math.Floor(time.Until(resp.TLS.PeerCertificates[0].NotAfter).Hours() / 24.0))
		if days < 0 {
			days = 0
		}
		res.CertDaysLeft = days
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		res.Passed = true
		return res
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		res.ErrorMessage = fmt.Sprintf("CRITICAL: MCP server accepted unauthenticated JSON-RPC initialize (HTTP %d)", resp.StatusCode)
		return res
	}
	res.ErrorMessage = fmt.Sprintf("MCP auth-gate returned unexpected HTTP %d", resp.StatusCode)
	return res
}

func runHTTP(ctx context.Context, c config.CheckConfig) Result {
	traceID, traceparent := newW3CTraceParent()
	res := Result{
		Name:            c.Name,
		Group:           c.Group,
		Kind:            "http",
		Target:          c.Target,
		TraceID:         traceID,
		RemainingTokens: -1,
		MCPToolsCount:   -1,
		CertDaysLeft:    -1,
		CheckedAt:       time.Now().UTC(),
	}

	targetURL := c.Target
	if !strings.Contains(targetURL, "://") {
		targetURL = "https://" + targetURL
	}
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Host == "" {
		res.ErrorMessage = "invalid target URL"
		return res
	}

	tlsCfg, err := buildTLSConfig(c, parsed.Hostname())
	if err != nil {
		res.ErrorMessage = err.Error()
		return res
	}

	var dnsStart, dnsDone, tcpStart, tcpDone, tlsStart, tlsDone, gotFirstByte time.Time
	var peerCertExpiry time.Time

	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tlsCfg,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: c.Timeout,
		DialContext:         (&net.Dialer{Timeout: c.Timeout}).DialContext,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   c.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}

	ht := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart: func(_, _ string) {
			if tcpStart.IsZero() {
				tcpStart = time.Now()
			}
		},
		ConnectDone: func(_, _ string, err error) {
			if err == nil && tcpDone.IsZero() {
				tcpDone = time.Now()
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsDone = time.Now()
			if err == nil && len(state.PeerCertificates) > 0 {
				peerCertExpiry = state.PeerCertificates[0].NotAfter
			}
		},
		GotFirstResponseByte: func() { gotFirstByte = time.Now() },
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, ht), c.Method, targetURL, nil)
	if err != nil {
		res.ErrorMessage = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "InferPing-Probe/1.0 (+https://github.com/inferping/inferping-probe)")
	req.Header.Set("traceparent", traceparent)
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	res.TotalMS = durMS(time.Since(start))
	if !dnsStart.IsZero() && !dnsDone.IsZero() {
		res.DNSMS = durMS(dnsDone.Sub(dnsStart))
	}
	if !tcpStart.IsZero() && !tcpDone.IsZero() {
		res.TCPMS = durMS(tcpDone.Sub(tcpStart))
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		res.TLSMS = durMS(tlsDone.Sub(tlsStart))
	}
	if !gotFirstByte.IsZero() {
		res.TTFBMS = durMS(gotFirstByte.Sub(start))
		res.TTFTMS = res.TTFBMS
	}
	if !peerCertExpiry.IsZero() {
		days := int(math.Floor(time.Until(peerCertExpiry).Hours() / 24.0))
		if days < 0 {
			days = 0
		}
		res.CertDaysLeft = days
	}

	if err != nil {
		res.ErrorMessage = compactErr(err)
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	res.TotalMS = durMS(time.Since(start))

	statusOK := resp.StatusCode >= 200 && resp.StatusCode < 400
	if c.ExpectStatus > 0 {
		statusOK = resp.StatusCode == c.ExpectStatus
	}
	if !statusOK {
		res.ErrorMessage = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return res
	}
	if c.Keyword != "" && !strings.Contains(string(bodyBytes), c.Keyword) {
		res.ErrorMessage = fmt.Sprintf("missing expected keyword %q", c.Keyword)
		return res
	}

	res.Passed = true
	return res
}

func runTCP(ctx context.Context, c config.CheckConfig) Result {
	traceID, _ := newW3CTraceParent()
	res := Result{
		Name:            c.Name,
		Group:           c.Group,
		Kind:            "tcp",
		Target:          c.Target,
		TraceID:         traceID,
		RemainingTokens: -1,
		MCPToolsCount:   -1,
		CertDaysLeft:    -1,
		CheckedAt:       time.Now().UTC(),
	}

	raw := strings.TrimSpace(c.Target)
	useTLS := strings.HasPrefix(strings.ToLower(raw), "tls://")
	for _, pfx := range []string{"tcp://", "tls://"} {
		if strings.HasPrefix(strings.ToLower(raw), pfx) {
			raw = raw[len(pfx):]
			break
		}
	}
	host, _, splitErr := net.SplitHostPort(raw)
	if splitErr != nil {
		res.ErrorMessage = fmt.Sprintf("invalid host:port %q", raw)
		return res
	}

	start := time.Now()
	d := net.Dialer{Timeout: c.Timeout}
	conn, err := d.DialContext(ctx, "tcp", raw)
	if err != nil {
		res.TotalMS = durMS(time.Since(start))
		res.StatusCode = 503
		res.ErrorMessage = compactErr(err)
		return res
	}
	defer conn.Close()
	res.TCPMS = durMS(time.Since(start))

	if useTLS {
		tlsCfg, cfgErr := buildTLSConfig(c, host)
		if cfgErr != nil {
			res.ErrorMessage = cfgErr.Error()
			return res
		}
		tlsStart := time.Now()
		tlsConn := tls.Client(conn, tlsCfg)
		_ = tlsConn.SetDeadline(time.Now().Add(c.Timeout))
		if hErr := tlsConn.HandshakeContext(ctx); hErr != nil {
			res.TotalMS = durMS(time.Since(start))
			res.StatusCode = 503
			res.ErrorMessage = compactErr(hErr)
			return res
		}
		res.TLSMS = durMS(time.Since(tlsStart))
		st := tlsConn.ConnectionState()
		if len(st.PeerCertificates) > 0 {
			days := int(math.Floor(time.Until(st.PeerCertificates[0].NotAfter).Hours() / 24.0))
			if days < 0 {
				days = 0
			}
			res.CertDaysLeft = days
		}
	}

	res.TotalMS = durMS(time.Since(start))
	res.StatusCode = 200
	res.Passed = true
	return res
}

func runDNS(ctx context.Context, c config.CheckConfig) Result {
	traceID, _ := newW3CTraceParent()
	res := Result{
		Name:            c.Name,
		Group:           c.Group,
		Kind:            "dns",
		Target:          c.Target,
		TraceID:         traceID,
		RemainingTokens: -1,
		MCPToolsCount:   -1,
		CertDaysLeft:    -1,
		CheckedAt:       time.Now().UTC(),
	}

	domain := strings.TrimSpace(c.Target)
	if strings.HasPrefix(strings.ToLower(domain), "dns://") {
		domain = strings.TrimSpace(domain[6:])
	}
	domain = strings.TrimRight(domain, "/")

	resolver := net.DefaultResolver
	if srv := strings.TrimSpace(c.DNSServer); srv != "" {
		if !strings.Contains(srv, ":") {
			srv = srv + ":53"
		}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: c.Timeout}
				return d.DialContext(ctx, network, srv)
			},
		}
	}

	start := time.Now()
	addrs, err := resolver.LookupHost(ctx, domain)
	elapsed := durMS(time.Since(start))
	res.DNSMS = elapsed
	res.TotalMS = elapsed

	if err != nil || len(addrs) == 0 {
		res.StatusCode = 503
		if err != nil {
			res.ErrorMessage = compactErr(err)
		} else {
			res.ErrorMessage = "no A or AAAA records returned"
		}
		return res
	}

	res.StatusCode = 200
	res.Passed = true
	return res
}

func extractJSONFromSSEOrBody(raw []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return trimmed
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "data:") {
			d := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if strings.HasPrefix(d, "{") {
				return []byte(d)
			}
		}
	}
	return trimmed
}

func parseHeaderInt64(h http.Header, keys ...string) int64 {
	for _, k := range keys {
		if v := strings.TrimSpace(h.Get(k)); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				return n
			}
		}
	}
	return -1
}

func durMS(d time.Duration) float64 {
	return math.Round(float64(d)/float64(time.Microsecond)) / 1000.0
}

func compactErr(err error) string {
	if err == nil {
		return ""
	}
	s := strings.TrimSpace(err.Error())
	if len(s) > 160 {
		return s[:160]
	}
	return s
}
