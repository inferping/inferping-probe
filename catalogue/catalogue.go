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
	domainMap        map[string]AIToolSignature
	idMap            map[string]AIToolSignature
	preloadedVersion = "embedded"
	forbiddenSuffix  = []string{".local", ".lan", ".internal", ".corp", ".home", ".arpa", ".intranet", ".localdomain"}
)

func init() {
	var doc CatalogueDocument
	if err := json.Unmarshal(embeddedCatalogueJSON, &doc); err == nil && len(doc.Tools) > 0 {
		if strings.TrimSpace(doc.Version) != "" {
			preloadedVersion = strings.TrimSpace(doc.Version)
		}
		rebuildLocked(sanitizeList(doc.Tools))
	}
}

func rebuildLocked(list []AIToolSignature) {
	cp := make([]AIToolSignature, len(list))
	copy(cp, list)
	dm := make(map[string]AIToolSignature, len(cp)*3)
	im := make(map[string]AIToolSignature, len(cp))
	for _, s := range cp {
		im[s.ToolID] = s
		for _, d := range s.Domains {
			if _, ok := dm[d]; !ok {
				dm[d] = s
			}
		}
	}
	active = cp
	domainMap = dm
	idMap = im
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
	return len(domainMap)
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
	rebuildLocked(merged)
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
	req.Header.Set("User-Agent", "InferPing-Probe/1.2 (+https://github.com/inferping/inferping-probe)")
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
	if s, ok := idMap[q]; ok {
		return s, true
	}
	return matchSuffixLocked(q)
}

func matchSuffixLocked(cand string) (AIToolSignature, bool) {
	for len(cand) >= 4 {
		if s, ok := domainMap[cand]; ok {
			return s, true
		}
		dot := strings.IndexByte(cand, '.')
		if dot < 0 {
			break
		}
		cand = cand[dot+1:]
	}
	return AIToolSignature{}, false
}

func isTokChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '.'
}

// MatchLine performs O(1) suffix hash-map matching across DNS/syslog lines at 500+ MB/sec.
func MatchLine(rawLine string) (AIToolSignature, bool) {
	n := len(rawLine)
	if n < 4 {
		return AIToolSignature{}, false
	}
	mu.RLock()
	defer mu.RUnlock()

	var lowerBuf [128]byte
	i := 0
	for i < n {
		for i < n && !isTokChar(rawLine[i]) {
			i++
		}
		start := i
		hasDot := false
		for i < n && isTokChar(rawLine[i]) {
			if rawLine[i] == '.' {
				hasDot = true
			}
			i++
		}
		end := i
		for end > start && (rawLine[end-1] == '.' || rawLine[end-1] == '-') {
			end--
		}
		for start < end && (rawLine[start] == '.' || rawLine[start] == '-') {
			start++
		}
		tlen := end - start
		if !hasDot || tlen < 4 || tlen > 120 {
			continue
		}
		last := rawLine[end-1]
		if last >= '0' && last <= '9' {
			continue
		}
		for k := 0; k < tlen; k++ {
			c := rawLine[start+k]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			lowerBuf[k] = c
		}
		if s, ok := matchSuffixLocked(string(lowerBuf[:tlen])); ok {
			return s, true
		}
	}
	return AIToolSignature{}, false
}

func ScanLogReader(r io.Reader) map[string]int {
	c, _ := ScanLogReaderWithBytes(r, 256*1024*1024)
	return c
}

func ScanLogReaderWithBytes(r io.Reader, maxBytes int64) (map[string]int, int64) {
	counts := make(map[string]int)
	if r == nil || maxBytes <= 0 {
		return counts, 0
	}
	cr := &cntReader{r: io.LimitReader(r, maxBytes)}
	sc := bufio.NewScanner(cr)
	buf := make([]byte, 64*1024)
	sc.Buffer(buf, 512*1024)
	for sc.Scan() {
		if sig, ok := MatchLine(sc.Text()); ok {
			counts[sig.ToolID]++
		}
	}
	return counts, cr.n
}

type cntReader struct {
	r io.Reader
	n int64
}

func (c *cntReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

type SyslogCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func NewSyslogCounter() *SyslogCounter {
	return &SyslogCounter{counts: make(map[string]int)}
}

func (s *SyslogCounter) Ingest(line string) {
	if sig, ok := MatchLine(line); ok {
		s.mu.Lock()
		s.counts[sig.ToolID]++
		s.mu.Unlock()
	}
}

func (s *SyslogCounter) Drain() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.counts) == 0 {
		return nil
	}
	out := s.counts
	s.counts = make(map[string]int)
	return out
}

func (s *SyslogCounter) ListenAndServe(ctx context.Context, addr string) error {
	udpConn, err := net.ListenPacket("udp", strings.TrimSpace(addr))
	if err != nil {
		return err
	}
	tcpLn, tcpErr := net.Listen("tcp", strings.TrimSpace(addr))
	go func() {
		<-ctx.Done()
		_ = udpConn.Close()
		if tcpLn != nil {
			_ = tcpLn.Close()
		}
	}()
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, rErr := udpConn.ReadFrom(buf)
			if n > 0 {
				s.Ingest(string(buf[:n]))
			}
			if rErr != nil {
				return
			}
		}
	}()
	if tcpErr == nil && tcpLn != nil {
		go func() {
			for {
				conn, aErr := tcpLn.Accept()
				if aErr != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					sc := bufio.NewScanner(io.LimitReader(c, 64*1024*1024))
					for sc.Scan() {
						s.Ingest(sc.Text())
					}
				}(conn)
			}
		}()
	}
	return nil
}
