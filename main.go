package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	httpClient  = &http.Client{Timeout: 18 * time.Second}
	// simple user agent to reduce bot blocking
	userAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
)

// crtEntry maps crt.sh JSON output fields (we only need name_value)
type crtEntry struct {
	NameValue string `json:"name_value"`
}

// certSpotterEntry maps certspotter JSON structure (common_name and dns_names)
type certSpotterEntry struct {
	CommonName string   `json:"common_name"`
	DNSNames   []string `json:"dns_names"`
}

func main() {
	targets := gatherTargets()

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: cat domains.txt | smapper")
		os.Exit(1)
	}

	results := enumerateForTargets(targets)
	for _, d := range results {
		fmt.Println(d)
	}
}

// gatherTargets reads targets from CLI args, file or stdin (in that order)
func gatherTargets() []string {
	targets := []string{}

	// 1) CLI args
	for _, a := range flag.Args() {
		a = strings.TrimSpace(a)
		if a != "" {
			targets = append(targets, sanitizeDomain(a))
		}
	}

	// 2) stdin (if piped)
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				targets = append(targets, sanitizeDomain(line))
			}
		}
	}

	// dedupe
	set := map[string]struct{}{}
	out := []string{}
	for _, t := range targets {
		if t == "" {
			continue
		}
		if _, ok := set[t]; ok {
			continue
		}
		set[t] = struct{}{}
		out = append(out, t)
	}
	return out
}


// enumerateForTargets runs multiple enumeration sources for each target and resolves hosts, dedups results.
func enumerateForTargets(targets []string) []string {
	outCh := make(chan string, 1024)
	var wg sync.WaitGroup

	// concurrency limiter for network calls (increase to maximize coverage but be polite)
	sem := make(chan struct{}, 20)

	for _, t := range targets {
		domain := strings.ToLower(strings.TrimSpace(t))
		if domain == "" {
			continue
		}
		wg.Add(1)
		go func(d string) {
			defer wg.Done()

			// Sources: crt.sh and certspotter (fallbacks inside functions)
			sem <- struct{}{}
			crt := queryCrtSh(d)
			<-sem

			sem <- struct{}{}
			cs := queryCertSpotter(d)
			<-sem

			// merge sources and emit
			seen := map[string]struct{}{}
			for k := range crt {
				if k != "" && strings.HasSuffix(k, "."+d) || k == d {
					clean := normalizeHost(k)
					if clean != "" {
						seen[clean] = struct{}{}
					}
				}
			}
			for k := range cs {
				if k != "" && (strings.HasSuffix(k, "."+d) || k == d) {
					clean := normalizeHost(k)
					if clean != "" {
						seen[clean] = struct{}{}
					}
				}
			}

			// also attempt to query crt.sh with naked domain (no wildcard) for different records
			sem <- struct{}{}
			crt2 := queryCrtShExact(d)
			<-sem
			for k := range crt2 {
				clean := normalizeHost(k)
				if clean != "" {
					seen[clean] = struct{}{}
				}
			}

			// emit unique
			for s := range seen {
				outCh <- s
			}
		}(domain)
	}

	go func() {
		wg.Wait()
		close(outCh)
	}()

	// collect and dedupe; validate via DNS lookups (A/CNAME)
	set := map[string]struct{}{}
	var mu sync.Mutex
	var resolverWg sync.WaitGroup

	for s := range outCh {
		// perform resolution concurrently but bounded
		resolverWg.Add(1)
		go func(host string) {
			defer resolverWg.Done()
			// best-effort resolution: consider alive if A, AAAA or CNAME present
			if isResolvable(host) {
				mu.Lock()
				set[host] = struct{}{}
				mu.Unlock()
				return
			}
			// even if not resolvable, include probable hosts (ex: asset storage) — attempt HTTP probe
			if probeHTTP(host) {
				mu.Lock()
				set[host] = struct{}{}
				mu.Unlock()
			}
		}(s)
	}

	resolverWg.Wait()

	// make sorted slice
	res := make([]string, 0, len(set))
	for k := range set {
		res = append(res, k)
	}
	sort.Strings(res)
	return res
}

// queryCrtSh queries crt.sh JSON endpoint for subdomains of domain d
// returns a set map of domains
func queryCrtSh(domain string) map[string]struct{} {
	out := map[string]struct{}{}
	u := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(domain))
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return out
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return out
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil || len(body) == 0 {
		return out
	}

	// try JSON parse
	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err == nil {
		for _, e := range entries {
			for _, line := range strings.Split(e.NameValue, "\n") {
				clean := strings.TrimSpace(line)
				clean = strings.TrimPrefix(clean, "*.")
				clean = strings.Trim(clean, ".")
				if clean != "" {
					out[clean] = struct{}{}
				}
			}
		}
		return out
	}

	// fallback regex extraction (robust for non-standard responses)
	r := regexp.MustCompile(`[A-Za-z0-9._-]+\.` + regexp.QuoteMeta(domain))
	matches := r.FindAllString(string(body), -1)
	for _, m := range matches {
		c := strings.Trim(m, ".")
		c = strings.TrimPrefix(c, "*.")
		out[c] = struct{}{}
	}
	return out
}

// queryCrtShExact queries crt.sh for entries that include the exact domain (no %25) — sometimes returns different set
func queryCrtShExact(domain string) map[string]struct{} {
	out := map[string]struct{}{}
	u := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(domain))
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return out
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return out
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || len(body) == 0 {
		return out
	}
	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err == nil {
		for _, e := range entries {
			for _, line := range strings.Split(e.NameValue, "\n") {
				clean := strings.TrimSpace(line)
				clean = strings.TrimPrefix(clean, "*.")
				clean = strings.Trim(clean, ".")
				if clean != "" {
					out[clean] = struct{}{}
				}
			}
		}
		return out
	}
	// regex fallback
	r := regexp.MustCompile(`[A-Za-z0-9._-]+\.` + regexp.QuoteMeta(domain))
	matches := r.FindAllString(string(body), -1)
	for _, m := range matches {
		c := strings.Trim(m, ".")
		c = strings.TrimPrefix(c, "*.")
		out[c] = struct{}{}
	}
	return out
}

// queryCertSpotter queries certspotter (public CT aggregator) as a complementary source
func queryCertSpotter(domain string) map[string]struct{} {
	out := map[string]struct{}{}
	// public endpoint for domain issuances
	u := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", url.QueryEscape(domain))
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return out
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// sometimes CertSpotter may rate limit (429) or block; just return empty
		return out
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil || len(body) == 0 {
		return out
	}

	var entries []certSpotterEntry
	if err := json.Unmarshal(body, &entries); err == nil {
		for _, e := range entries {
			cleanAndAdd(out, e.CommonName)
			for _, n := range e.DNSNames {
				cleanAndAdd(out, n)
			}
		}
		return out
	}

	// fallback regex extraction
	r := regexp.MustCompile(`[A-Za-z0-9._-]+\.` + regexp.QuoteMeta(domain))
	matches := r.FindAllString(string(body), -1)
	for _, m := range matches {
		out[strings.Trim(m, ".")] = struct{}{}
	}
	return out
}

func cleanAndAdd(m map[string]struct{}, s string) {
	if s == "" {
		return
	}
	for _, part := range strings.Split(s, "\n") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "*.")
		part = strings.Trim(part, ".")
		if part != "" {
			m[part] = struct{}{}
		}
	}
}

// isResolvable tries to resolve the host (A/AAAA/CNAME). returns true if resolved
func isResolvable(host string) bool {
	if host == "" {
		return false
	}
	// quick accept if raw IP
	if net.ParseIP(host) != nil {
		return true
	}

	// try LookupHost (A/AAAA)
	done := make(chan bool, 1)
	go func() {
		_, err := net.LookupHost(host)
		done <- (err == nil)
	}()
	select {
	case ok := <-done:
		if ok {
			return true
		}
	case <-time.After(4 * time.Second):
		// timed out; continue to try CNAME probe
	}

	// try LookupCNAME
	cnameDone := make(chan bool, 1)
	go func() {
		_, err := net.LookupCNAME(host)
		cnameDone <- (err == nil)
	}()
	select {
	case ok := <-cnameDone:
		return ok
	case <-time.After(3 * time.Second):
		return false
	}
}

// probeHTTP makes a basic HTTP HEAD probe to check whether host answers on common ports (80/443).
// Returns true if it gets any HTTP response.
func probeHTTP(host string) bool {
	// try http and https
	ports := []string{"https://", "http://"}
	for _, p := range ports {
		u := p + host
		req, err := http.NewRequest("HEAD", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := httpClient.Do(req)
		if err == nil {
			resp.Body.Close()
			// any 2xx/3xx/4xx indicates a server responded
			if resp.StatusCode >= 100 && resp.StatusCode < 600 {
				return true
			}
		}
	}
	return false
}

// normalizeHost tidy hostnames
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.Trim(h, ".")
	h = strings.TrimPrefix(h, "*.")
	// strip ports, paths if any
	if idx := strings.IndexAny(h, "/:"); idx != -1 {
		h = h[:idx]
	}
	// basic validation
	re := regexp.MustCompile(`[^a-z0-9\.\-]`)
	h = re.ReplaceAllString(h, "")
	// avoid empty or leading dash
	h = strings.Trim(h, "-")
	return h
}

// sanitizeDomain extracts the domain portion from input
func sanitizeDomain(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// if user passed a URL, parse it
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		u, err := url.Parse(s)
		if err == nil {
			return u.Hostname()
		}
	}
	// remove path if present
	if idx := strings.IndexAny(s, "/:\\"); idx != -1 {
		s = s[:idx]
	}
	// basic validation: keep only valid hostname chars, lowercase
	re := regexp.MustCompile(`[^A-Za-z0-9\.\-]`)
	s = re.ReplaceAllString(s, "")
	return strings.ToLower(strings.TrimSpace(s))
}
