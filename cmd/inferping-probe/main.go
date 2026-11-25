package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/inferping/inferping-probe/catalogue"
	"github.com/inferping/inferping-probe/internal/checker"
	"github.com/inferping/inferping-probe/internal/config"
	"github.com/inferping/inferping-probe/internal/otlp"
)

var version = "1.2.0"

func main() {
	var (
		configPath       = flag.String("config", defaultConfigPath(), "Path to inferping.yaml or inferping.json (optional if INFERPING_TARGETS or -mode is set)")
		runOnce          = flag.Bool("once", false, "Run all configured checks once, push OTLP metrics, and exit")
		dryRun           = flag.Bool("dry-run", false, "Run checks and print results without pushing to the OTLP endpoint")
		showVersion      = flag.Bool("version", false, "Print version and exit")
		modeFlag         = flag.String("mode", "", "Direct single-mode execution: ai-discovery, llm, mcp, mcp-gate, or http")
		urlFlag          = flag.String("url", "", "Target URL when using -mode=llm|mcp|mcp-gate|http")
		modelFlag        = flag.String("model", "mistral-small-latest", "Model ID when using -mode=llm")
		serviceNameFlag  = flag.String("service-name", "Internal-AI-Check", "Service monitor name when using -mode")
		serviceGroupFlag = flag.String("service-group", "", "Optional Service Group name when using -mode")
		regionFlag       = flag.String("region", "", "Probe region/site identifier (e.g. hq-amsterdam, plant-munich)")
		authEnvFlag      = flag.String("auth-env", "LLM_API_KEY", "Environment variable holding local LLM/MCP Bearer key")
		expectToolsFlag  = flag.Int("expect-tools", 1, "Minimum tool count for -mode=mcp")
		expectHashFlag   = flag.String("expect-schema-hash", "", "Optional 16-hex SHA-256 tool schema lock hash for -mode=mcp")
		dnsLogFlag       = flag.String("dns-log", "", "Path to DNS resolver or firewall log file for -mode=ai-discovery (strips employee IPs locally)")
		syslogListenFlag = flag.String("syslog-listen", "", "Optional UDP+TCP syslog listen address (e.g. 127.0.0.1:5514) for zero-disk enterprise Shadow-AI discovery")
		fromStartFlag    = flag.Bool("from-start", false, "Read existing -dns-log from byte 0 on startup instead of tailing from EOF")
		airgappedFlag    = flag.Bool("airgapped", false, "Airgapped/offline mode: disable central AI catalogue sync and use strictly the preloaded embedded catalogue (+ optional -catalogue-file)")
		catalogueURLFlag = flag.String("catalogue-url", "https://app.inferping.eu/v1/ai-catalogue.json", "Central AI tool domain catalogue URL synced every 12h in ai-discovery mode")
		catalogueFile    = flag.String("catalogue-file", "", "Optional local JSON file with extra AI tool domains to merge into the preloaded catalogue")
		pushURLFlag      = flag.String("push-url", "https://app.inferping.eu/v1/metrics", "OTLP/HTTP metrics ingest URL for -mode execution")
		intervalFlag     = flag.Duration("interval", 0, "Continuous interval for -mode execution (e.g. 60s); defaults to 60s when -syslog-listen is set")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("inferping-probe v%s (https://github.com/inferping/inferping-probe, preloaded AI catalogue %s with %d domains)\n", version, catalogue.Version(), catalogue.DomainCount())
		return
	}

	if strings.TrimSpace(*catalogueFile) != "" {
		if n, lErr := catalogue.LoadFile(*catalogueFile); lErr != nil {
			log.Printf("[inferping-probe] warning loading -catalogue-file: %v", lErr)
		} else {
			log.Printf("[inferping-probe] merged %d custom AI tool entries from %s", n, *catalogueFile)
		}
	}

	cleanMode := strings.ToLower(strings.TrimSpace(*modeFlag))
	if cleanMode == "ai-discovery" || strings.TrimSpace(*dnsLogFlag) != "" || strings.TrimSpace(*syslogListenFlag) != "" {
		runAIDiscoveryLoop(*dnsLogFlag, *syslogListenFlag, *regionFlag, *pushURLFlag, *catalogueURLFlag, *airgappedFlag, *fromStartFlag, *dryRun, *intervalFlag)
		return
	}

	if cleanMode != "" && strings.TrimSpace(*urlFlag) != "" {
		runDirectCheckLoop(cleanMode, *urlFlag, *modelFlag, *serviceNameFlag, *serviceGroupFlag, *regionFlag, *authEnvFlag, *expectToolsFlag, *expectHashFlag, *pushURLFlag, *dryRun, *intervalFlag)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("[inferping-probe] configuration error: %v", err)
	}
	if strings.TrimSpace(*regionFlag) != "" {
		cfg.Region = strings.TrimSpace(*regionFlag)
	}
	if !*dryRun && cfg.APIKey == "" {
		log.Printf("[inferping-probe] warning: INFERPING_API_KEY is empty (set api_key or INFERPING_API_KEY for https://app.inferping.eu)")
	}

	exporter := otlp.NewExporter(cfg.Endpoint, cfg.APIKey, cfg.Region, cfg.Headers)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *runOnce {
		os.Exit(executeOnce(ctx, cfg, exporter, *dryRun))
	}

	log.Printf("[inferping-probe] v%s started (region=%s, checks=%d, endpoint=%s)", version, cfg.Region, len(cfg.Checks), cfg.Endpoint)

	resultsCh := make(chan checker.Result, len(cfg.Checks)*4+16)
	var wg sync.WaitGroup

	for idx, chk := range cfg.Checks {
		c := chk
		stagger := time.Duration(idx*150) * time.Millisecond
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case <-time.After(stagger):
			}
			runAndQueue := func() {
				res := checker.Run(ctx, c)
				if res.Passed {
					log.Printf("[OK]   %-28s kind=%-8s status=%-3d total=%6.1fms ttft=%6.1fms", res.Name, res.Kind, res.StatusCode, res.TotalMS, res.TTFTMS)
				} else {
					log.Printf("[FAIL] %-28s kind=%-8s status=%-3d total=%6.1fms (%s)", res.Name, res.Kind, res.StatusCode, res.TotalMS, res.ErrorMessage)
				}
				select {
				case resultsCh <- res:
				default:
				}
			}
			runAndQueue()
			ticker := time.NewTicker(c.Interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					runAndQueue()
				}
			}
		}()
	}

	flushTicker := time.NewTicker(2 * time.Second)
	defer flushTicker.Stop()
	var batch []checker.Result

	flush := func() {
		if len(batch) == 0 {
			return
		}
		toSend := make([]checker.Result, len(batch))
		copy(toSend, batch)
		batch = batch[:0]
		if *dryRun {
			return
		}
		fctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		if exErr := exporter.Export(fctx, toSend); exErr != nil {
			log.Printf("[OTLP] push warning (%d check(s)): %v", len(toSend), exErr)
		}
	}

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			for {
				select {
				case r := <-resultsCh:
					batch = append(batch, r)
				default:
					flush()
					log.Printf("[inferping-probe] stopped cleanly")
					return
				}
			}
		case r := <-resultsCh:
			batch = append(batch, r)
			if len(batch) >= 25 {
				flush()
			}
		case <-flushTicker.C:
			flush()
		}
	}
}

func runAIDiscoveryLoop(logPath, syslogAddr, region, pushURL, catalogueURL string, airgapped, fromStart, dryRun bool, interval time.Duration) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if strings.TrimSpace(region) == "" {
		region = strings.TrimSpace(os.Getenv("INFERPING_REGION"))
		if region == "" {
			region = "office-vlan"
		}
	}
	apiKey := strings.TrimSpace(os.Getenv("INFERPING_API_KEY"))

	var sysCounter *catalogue.SyslogCounter
	if strings.TrimSpace(syslogAddr) != "" {
		sysCounter = catalogue.NewSyslogCounter()
		if err := sysCounter.ListenAndServe(ctx, syslogAddr); err != nil {
			log.Fatalf("[ai-discovery] failed binding -syslog-listen %s: %v", syslogAddr, err)
		}
		if interval <= 0 {
			interval = 60 * time.Second
		}
	}

	var (
		lastOffset  int64
		initialized bool
		lastSync    time.Time
		lastETag    string
	)
	maybeSync := func() {
		if airgapped || strings.TrimSpace(catalogueURL) == "" {
			return
		}
		if !lastSync.IsZero() && time.Since(lastSync) < 12*time.Hour {
			return
		}
		sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if etag, _, err := catalogue.SyncFromURL(sctx, catalogueURL, apiKey, lastETag); err == nil {
			lastETag = etag
		}
		lastSync = time.Now()
	}

	step := func() bool {
		maybeSync()
		counts := make(map[string]int)
		cleanPath := strings.TrimSpace(logPath)
		if cleanPath != "" {
			f, err := os.Open(cleanPath)
			if err != nil {
				log.Printf("[ai-discovery] error opening %s: %v", cleanPath, err)
				return false
			}
			st, err := f.Stat()
			if err != nil {
				f.Close()
				return false
			}
			if !initialized && !fromStart && interval > 0 && st.Size() > 512*1024 {
				lastOffset = st.Size()
				initialized = true
				f.Close()
			} else {
				initialized = true
				if st.Size() < lastOffset {
					lastOffset = 0
				}
				if lastOffset > 0 {
					_, _ = f.Seek(lastOffset, 0)
				}
				fc, consumed := catalogue.ScanLogReaderWithBytes(f, 256*1024*1024)
				lastOffset += consumed
				f.Close()
				for k, v := range fc {
					counts[k] += v
				}
			}
		} else if sysCounter == nil {
			log.Printf("[ai-discovery] error: specify -dns-log or -syslog-listen")
			return false
		}
		if sysCounter != nil {
			for k, v := range sysCounter.Drain() {
				counts[k] += v
			}
		}

		cleanPush := strings.TrimSpace(pushURL)
		if !dryRun && cleanPush != "" && len(counts) > 0 && (!airgapped || !strings.Contains(cleanPush, "inferping.eu")) {
			_ = pushDiscoveryOTLP(ctx, cleanPush, apiKey, region, counts)
		}
		out, _ := json.MarshalIndent(map[string]any{
			"mode":                    "ai-discovery",
			"passed":                  true,
			"airgapped":               airgapped,
			"region":                  region,
			"catalogue_version":       catalogue.Version(),
			"catalogue_domains":       catalogue.DomainCount(),
			"anonymized_tools_active": len(counts),
			"tool_hits":               counts,
			"pii_stripped":            true,
		}, "", "  ")
		fmt.Println(string(out))
		return true
	}

	if interval <= 0 {
		if !step() {
			os.Exit(1)
		}
		return
	}
	if sysCounter == nil {
		step()
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			step()
		}
	}
}

func pushDiscoveryOTLP(ctx context.Context, pushURL, apiKey, region string, counts map[string]int) error {
	var dps []map[string]any
	for toolID, hits := range counts {
		if hits <= 0 {
			continue
		}
		dom := toolID
		if sig, ok := catalogue.LookupByID(toolID); ok {
			dom = sig.PrimaryDomain
		}
		dps = append(dps, map[string]any{
			"asDouble": float64(hits),
			"attributes": []map[string]any{
				{"key": "ai.tool.id", "value": map[string]string{"stringValue": toolID}},
				{"key": "ai.tool.domain", "value": map[string]string{"stringValue": dom}},
			},
		})
	}
	if len(dps) == 0 {
		return nil
	}
	payload := map[string]any{
		"resourceMetrics": []map[string]any{{
			"resource": map[string]any{
				"attributes": []map[string]any{
					{"key": "service.name", "value": map[string]string{"stringValue": "inferping-ai-discovery"}},
					{"key": "probe.region", "value": map[string]string{"stringValue": region}},
				},
			},
			"scopeMetrics": []map[string]any{{
				"metrics": []map[string]any{{
					"name":  "inferping.ai.discovery.hits",
					"gauge": map[string]any{"dataPoints": dps},
				}},
			}},
		}},
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pushURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func runDirectCheckLoop(mode, targetURL, model, serviceName, serviceGroup, region, authEnv string, expectTools int, expectHash, pushURL string, dryRun bool, interval time.Duration) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if strings.TrimSpace(region) == "" {
		region = strings.TrimSpace(os.Getenv("INFERPING_REGION"))
		if region == "" {
			region = "vpc-eu-west"
		}
	}
	apiKey := strings.TrimSpace(os.Getenv("INFERPING_API_KEY"))
	ep := strings.TrimSuffix(strings.TrimSpace(pushURL), "/v1/metrics")
	exp := otlp.NewExporter(ep, apiKey, region, nil)
	chk := config.CheckConfig{
		Name:             serviceName,
		Group:            serviceGroup,
		Kind:             mode,
		Target:           targetURL,
		Model:            model,
		AuthEnv:          authEnv,
		ExpectTools:      expectTools,
		ExpectSchemaHash: expectHash,
		Timeout:          15 * time.Second,
	}
	step := func() bool {
		r := checker.Run(ctx, chk)
		if !dryRun && strings.TrimSpace(pushURL) != "" {
			_ = exp.Export(ctx, []checker.Result{r})
		}
		out, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(out))
		return r.Passed
	}
	if interval <= 0 {
		if !step() {
			os.Exit(1)
		}
		return
	}
	step()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			step()
		}
	}
}

func defaultConfigPath() string {
	if env := os.Getenv("INFERPING_CONFIG"); env != "" {
		return env
	}
	if _, err := os.Stat("inferping.yaml"); err == nil {
		return "inferping.yaml"
	}
	return ""
}

func executeOnce(ctx context.Context, cfg *config.Config, exporter *otlp.Exporter, dryRun bool) int {
	results := make([]checker.Result, len(cfg.Checks))
	var wg sync.WaitGroup
	for i, chk := range cfg.Checks {
		i, chk := i, chk
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = checker.Run(ctx, chk)
		}()
	}
	wg.Wait()

	failed := 0
	for _, r := range results {
		state := "OK"
		if !r.Passed {
			state = "FAIL"
			failed++
		}
		extra := r.ErrorMessage
		if r.Passed {
			if r.Kind == "llm" && r.TTFTMS > 0 {
				extra = fmt.Sprintf("TTFT=%.1fms", r.TTFTMS)
			} else if r.Kind == "mcp" && r.MCPToolsCount >= 0 {
				extra = fmt.Sprintf("tools=%d schema=%s", r.MCPToolsCount, r.MCPSchemaHash)
			} else if r.CertDaysLeft >= 0 {
				extra = fmt.Sprintf("TLS valid (%dd left)", r.CertDaysLeft)
			}
		}
		fmt.Printf("%-5s %-30s kind=%-8s status=%-3d total=%6.1fms  %s\n", state, r.Name, r.Kind, r.StatusCode, r.TotalMS, extra)
	}

	if !dryRun {
		if err := exporter.Export(ctx, results); err != nil {
			log.Printf("[OTLP] export error: %v", err)
			return 1
		}
		fmt.Printf("Pushed %d check result(s) via OTLP/HTTP to %s\n", len(results), cfg.Endpoint)
	}
	if failed > 0 {
		return 1
	}
	return 0
}
