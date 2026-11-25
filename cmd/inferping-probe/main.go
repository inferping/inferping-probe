package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/inferping/inferping-probe/internal/checker"
	"github.com/inferping/inferping-probe/internal/config"
	"github.com/inferping/inferping-probe/internal/otlp"
)

var version = "1.1.0"

func main() {
	var (
		configPath       = flag.String("config", defaultConfigPath(), "Path to inferping.yaml or inferping.json (optional if INFERPING_TARGETS or -mode is set)")
		runOnce          = flag.Bool("once", false, "Run all configured checks once, push OTLP metrics, and exit")
		dryRun           = flag.Bool("dry-run", false, "Run checks and print results without pushing to the OTLP endpoint")
		showVersion      = flag.Bool("version", false, "Print version and exit")
		modeFlag         = flag.String("mode", "", "Direct single-mode execution: llm, mcp, mcp-gate, or http")
		urlFlag          = flag.String("url", "", "Target URL when using -mode=llm|mcp|mcp-gate|http")
		modelFlag        = flag.String("model", "mistral-small-latest", "Model ID when using -mode=llm")
		serviceNameFlag  = flag.String("service-name", "Internal-AI-Check", "Service monitor name when using -mode")
		serviceGroupFlag = flag.String("service-group", "", "Optional Service Group name when using -mode")
		regionFlag       = flag.String("region", "", "Probe region/site identifier (e.g. k8s-eu-west, gpu-vpc-01)")
		authEnvFlag      = flag.String("auth-env", "LLM_API_KEY", "Environment variable holding local LLM/MCP Bearer key")
		expectToolsFlag  = flag.Int("expect-tools", 1, "Minimum tool count for -mode=mcp")
		expectHashFlag   = flag.String("expect-schema-hash", "", "Optional 16-hex SHA-256 tool schema lock hash for -mode=mcp")
		pushURLFlag      = flag.String("push-url", "https://app.inferping.eu/v1/metrics", "OTLP/HTTP metrics ingest URL for -mode execution")
		intervalFlag     = flag.Duration("interval", 0, "Continuous interval for -mode execution (e.g. 60s)")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("inferping-probe v%s (https://github.com/inferping/inferping-probe)\n", version)
		return
	}

	cleanMode := strings.ToLower(strings.TrimSpace(*modeFlag))
	if cleanMode == "ai-discovery" {
		log.Fatalf("[inferping-probe] passive DNS/log Shadow-AI counting now lives in the dedicated zero-probing collector: https://github.com/inferping/inferping-dns-collector")
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
			if err := exp.Export(ctx, []checker.Result{r}); err != nil {
				log.Printf("[OTLP] export warning: %v", err)
			}
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
