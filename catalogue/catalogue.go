package catalogue

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed ai-tools.json
var embeddedCatalogueJSON []byte

type AIToolSignature struct {
	ToolID               string   `json:"tool_id"`
	DisplayName          string   `json:"display_name"`
	Vendor               string   `json:"vendor"`
	Category             string   `json:"category"`
	Region               string   `json:"region"`
	PrimaryDomain        string   `json:"primary_domain"`
	Domains              []string `json:"domains"`
	DefaultPolicy        string   `json:"default_policy"`
	RiskNote             string   `json:"risk_note"`
	SuggestedAlternative string   `json:"suggested_alternative"`
}

type CatalogueDocument struct {
	Version     string            `json:"version"`
	UpdatedAt   string            `json:"updated_at"`
	Source      string            `json:"source,omitempty"`
	GitMirror   string            `json:"git_mirror,omitempty"`
	ToolCount   int               `json:"tool_count"`
	DomainCount int               `json:"domain_count"`
	Tools       []AIToolSignature `json:"tools"`
}

var (
	mu               sync.RWMutex
	active           []AIToolSignature
	preloadedVersion = "embedded"
	forbiddenSuffix  = []string{".local", ".lan", ".internal", ".corp", ".home", ".arpa", ".intranet", ".localdomain"}
)

func init() {
	var doc CatalogueDocument
	if err := json.Unmarshal(embeddedCatalogueJSON, &doc); err == nil && len(doc.Tools) > 0 {
		if strings.TrimSpace(doc.Version) != "" {
			preloadedVersion = strings.TrimSpace(doc.Version)
		}
		active = sanitizeList(doc.Tools)
	}
}

func IsSafePublicAIDomain(raw string) bool {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if len(d) < 4 || len(d) > 96 || !strings.Contains(d, ".") || d == "localhost" || net.ParseIP(d) != nil {
		return false
	}
	for _, suf := range forbiddenSuffix {
		if strings.HasSuffix(d, suf) {
			return false
		}
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 || len(labels[len(labels)-1]) < 2 {
		return false
	}
	for _, lbl := range labels {
		if len(lbl) == 0 || len(lbl) > 63 || lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return false
		}
		for i := 0; i < len(lbl); i++ {
			c := lbl[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func sanitizeList(in []AIToolSignature) []AIToolSignature {
	out := make([]AIToolSignature, 0, len(in))
	seen := make(map[string]int, len(in))
	for _, s := range in {
		if len(out) >= 500 {
			break
		}
		s.ToolID = strings.ToLower(strings.TrimSpace(s.ToolID))
		s.PrimaryDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.PrimaryDomain), "."))
		if s.PrimaryDomain == "" && len(s.Domains) > 0 {
			s.PrimaryDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.Domains[0]), "."))
		}
		if !IsSafePublicAIDomain(s.PrimaryDomain) {
			continue
		}
		if s.ToolID == "" || len(s.ToolID) > 96 {
			s.ToolID = s.PrimaryDomain
		}
		var doms []string
		dseen := map[string]struct{}{}
		for _, cand := range append([]string{s.PrimaryDomain}, s.Domains...) {
			c := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cand), "."))
			if IsSafePublicAIDomain(c) && len(doms) < 16 {
				if _, ok := dseen[c]; !ok {
					dseen[c] = struct{}{}
					doms = append(doms, c)
				}
			}
		}
		s.Domains = doms
		if idx, ok := seen[s.ToolID]; ok {
			out[idx] = s
		} else {
			seen[s.ToolID] = len(out)
			out = append(out, s)
		}
	}
	return out
}

func Version() string { return preloadedVersion }

func DomainCount() int {
	mu.RLock()
	defer mu.RUnlock()
	u := make(map[string]struct{}, len(active)*3)
	for _, s := range active {
		for _, d := range s.Domains {
			u[d] = struct{}{}
		}
	}
	return len(u)
}

func Merge(ext []AIToolSignature) int {
	valid := sanitizeList(ext)
	if len(valid) == 0 {
		return 0
	}
	mu.Lock()
	defer mu.Unlock()
	byID := make(map[string]int, len(active)+len(valid))
	merged := make([]AIToolSignature, len(active))
	copy(merged, active)
	for i, s := range merged {
		byID[s.ToolID] = i
	}
	for _, v := range valid {
		if len(merged) >= 600 {
			break
		}
		if idx, ok := byID[v.ToolID]; ok {
			merged[idx] = v
		} else {
			byID[v.ToolID] = len(merged)
			merged = append(merged, v)
		}
	}
	active = merged
	return len(valid)
}

func LoadFile(path string) (int, error) {
	f, err := os.Open(strings.TrimSpace(path))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 2*1024*1024))
	if err != nil {
		return 0, err
	}
	return parseAndMerge(raw)
}

func parseAndMerge(raw []byte) (int, error) {
	t := strings.TrimSpace(string(raw))
	if strings.HasPrefix(t, "[") {
		var list []AIToolSignature
		if err := json.Unmarshal([]byte(t), &list); err != nil {
			return 0, err
		}
		return Merge(list), nil
	}
	var doc CatalogueDocument
	if err := json.Unmarshal([]byte(t), &doc); err != nil {
		return 0, err
	}
	return Merge(doc.Tools), nil
}

func SyncFromURL(ctx context.Context, url, apiKey, prevETag string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSpace(url), nil)
	if err != nil {
		return prevETag, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "InferPing-Probe/1.1 (+https://github.com/inferping/inferping-probe)")
	if prevETag != "" {
		req.Header.Set("If-None-Match", prevETag)
	}
	if strings.TrimSpace(apiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return prevETag, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return prevETag, 0, nil
	}
	if resp.StatusCode != http.StatusOK {
		return prevETag, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return prevETag, 0, err
	}
	n, err := parseAndMerge(raw)
	if err != nil {
		return prevETag, 0, err
	}
	etag := strings.TrimSpace(resp.Header.Get("ETag"))
	if etag == "" {
		etag = prevETag
	}
	return etag, n, nil
}

func LookupByID(toolID string) (AIToolSignature, bool) {
	q := strings.ToLower(strings.TrimSpace(toolID))
	mu.RLock()
	defer mu.RUnlock()
	for _, s := range active {
		if s.ToolID == q || s.PrimaryDomain == q {
			return s, true
		}
	}
	return AIToolSignature{}, false
}

func MatchLine(rawLine string) (AIToolSignature, bool) {
	low := strings.ToLower(rawLine)
	mu.RLock()
	defer mu.RUnlock()
	for _, s := range active {
		for _, dom := range s.Domains {
			idx := strings.Index(low, dom)
			if idx < 0 {
				continue
			}
			if idx > 0 {
				p := low[idx-1]
				if (p >= 'a' && p <= 'z') || (p >= '0' && p <= '9') || p == '-' {
					continue
				}
			}
			end := idx + len(dom)
			if end < len(low) {
				nx := low[end]
				if (nx >= 'a' && nx <= 'z') || (nx >= '0' && nx <= '9') || nx == '-' {
					continue
				}
			}
			return s, true
		}
	}
	return AIToolSignature{}, false
}

func ScanLogReader(r io.Reader) map[string]int {
	counts := make(map[string]int)
	if r == nil {
		return counts
	}
	sc := bufio.NewScanner(io.LimitReader(r, 16*1024*1024))
	for sc.Scan() {
		if sig, ok := MatchLine(sc.Text()); ok {
			counts[sig.ToolID]++
		}
	}
	return counts
}
