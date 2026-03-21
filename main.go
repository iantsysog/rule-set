package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/coregx/coregex"
	"github.com/iantsysog/sing-rule/convertor/asn"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"golang.org/x/sys/unix"
)

const (
	httpTimeout     = 10 * time.Second
	httpPoolTimeout = 30 * time.Second
	maxConnections  = 100
	maxKeepalive    = 20
	scannerBufSize  = 64 * 1024
	scannerMaxSize  = 1024 * 1024
	filePerm        = 0o644
	dirPerm         = 0o755
)

var (
	excludedAddresses = map[string]struct{}{
		"":  {},
		"#": {},
		"th1s_rule5et_1s_m4d3_by_5ukk4w_ruleset.skk.moe": {},
		"7h1s_rul35et_i5_mad3_by_5ukk4w-ruleset.skk.moe": {},
	}

	bufferPool = sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}

	scannerBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, scannerBufSize)
			return &b
		},
	}

	regexValidationCache sync.Map
)

var logicalRuleKeys = map[string]struct{}{
	"AND": {},
	"OR":  {},
	"NOT": {},
}

type ruleEntry struct {
	pattern string
	address string
}

type ruleFrame struct {
	entries []ruleEntry
	groups  map[string][]string
}

type fileInfo struct {
	path     string
	category string
	name     string
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, unix.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		slog.Error("run failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	listDir := findDirectory("List", "../List")
	modulesDir := findDirectory(
		"Modules/Rules/sukka_local_dns_mapping",
		"../Modules/Rules/sukka_local_dns_mapping",
	)
	if listDir == "" {
		return E.New("list directory not found")
	}

	client := newHTTPClient()
	defer client.CloseIdleConnections()

	subdirs := []string{"domainset", "ip", "non_ip", "dns"}
	sourceDir := "sing-box/go/source"
	binaryDir := "sing-box/go/binary"

	if err := ensureDirectories(sourceDir, subdirs); err != nil {
		return E.Cause(err, "create source directories")
	}
	if err := ensureDirectories(binaryDir, subdirs); err != nil {
		return E.Cause(err, "create binary directories")
	}

	confFiles, err := collectFiles(listDir, []string{"domainset", "ip", "non_ip"})
	if err != nil {
		return E.Cause(err, "collect files")
	}
	if modulesDir != "" {
		dnsFiles, err := collectFiles(modulesDir, []string{"dns"})
		if err == nil {
			confFiles = append(confFiles, dnsFiles...)
		}
	}

	b, bctx := batch.New(ctx, batch.WithConcurrencyNum[struct{}](maxConnections))
	resolver, err := asn.NewASNResolver()
	if err != nil {
		return E.Cause(err, "create ASN resolver")
	}

	for _, file := range confFiles {
		file := file
		b.Go(file.path, func() (struct{}, error) {
			return struct{}{}, processFile(bctx, client, resolver, file, sourceDir, binaryDir)
		})
	}

	if err := b.Wait(); err != nil {
		return err
	}
	return nil
}

func processFile(ctx context.Context, client *http.Client, resolver *asn.ASNResolver, file fileInfo, sourceDir, binaryDir string) error {
	frame, err := prepareFrame(ctx, client, "file://"+file.path)
	if err != nil || frame == nil {
		return err
	}

	sourcePath := filepath.Join(sourceDir, file.category)
	binaryPath := filepath.Join(binaryDir, file.category)
	return emitFile(ctx, resolver, frame, sourcePath, binaryPath, file.name, file.category)
}

func findDirectory(paths ...string) string {
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	return ""
}

func ensureDirectories(baseDir string, subdirs []string) error {
	for _, sub := range subdirs {
		if err := os.MkdirAll(filepath.Join(baseDir, sub), dirPerm); err != nil {
			return err
		}
	}
	return nil
}

func collectFiles(dir string, categories []string) ([]fileInfo, error) {
	files := make([]fileInfo, 0, 64)

	for _, category := range categories {
		pattern := filepath.Join(dir, category, "*.conf")
		if category == "dns" {
			pattern = filepath.Join(dir, "*.conf")
		}

		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		sort.Strings(matches)

		for _, match := range matches {
			base := filepath.Base(match)
			if filepath.Ext(base) != ".conf" {
				continue
			}
			name := strings.TrimSuffix(base, ".conf")
			if name == "" {
				continue
			}
			files = append(files, fileInfo{
				path:     match,
				category: category,
				name:     name,
			})
		}
	}

	sort.Slice(files, func(i, j int) bool {
		if files[i].category != files[j].category {
			return files[i].category < files[j].category
		}
		if files[i].name != files[j].name {
			return files[i].name < files[j].name
		}
		return files[i].path < files[j].path
	})

	return files, nil
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        maxKeepalive,
			MaxConnsPerHost:     maxConnections,
			IdleConnTimeout:     httpPoolTimeout,
			DisableCompression:  false,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: maxKeepalive,
		},
	}
}

func prepareFrame(ctx context.Context, client *http.Client, source string) (*ruleFrame, error) {
	reader, err := openSource(ctx, client, source)
	if err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, nil
	}
	defer reader.Close()

	bufPtr := scannerBufPool.Get().(*[]byte)
	defer scannerBufPool.Put(bufPtr)

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(*bufPtr, scannerMaxSize)

	entries := make([]ruleEntry, 0, 256)
	seen := make(map[ruleEntry]struct{}, 256)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		entry := parseLine(line)
		if entry.pattern == "" || entry.address == "" {
			continue
		}
		if strings.Contains(entry.pattern, "#") {
			continue
		}
		if _, excluded := excludedAddresses[entry.address]; excluded {
			continue
		}
		if _, exists := seen[entry]; exists {
			continue
		}
		seen[entry] = struct{}{}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}

	groups := make(map[string][]string, len(entries))
	for _, entry := range entries {
		groups[entry.pattern] = append(groups[entry.pattern], entry.address)
	}

	return &ruleFrame{entries: entries, groups: groups}, nil
}

func openSource(ctx context.Context, client *http.Client, source string) (io.ReadCloser, error) {
	if after, ok := strings.CutPrefix(source, "file://"); ok {
		return os.Open(after)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, nil
	}
	return resp.Body, nil
}

func parseLine(line string) ruleEntry {
	pattern, rest, ok := strings.Cut(line, ",")
	if ok {
		pattern = strings.TrimSpace(pattern)
		rest = strings.TrimSpace(rest)
		if pattern == "" || rest == "" {
			return ruleEntry{}
		}

		addr, suffix, hasSuffix := strings.Cut(rest, ",")
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return ruleEntry{}
		}
		if hasSuffix {
			suffix = strings.TrimSpace(suffix)
			if suffix != "" {
				return ruleEntry{pattern: pattern, address: addr + "," + suffix}
			}
		}
		return ruleEntry{pattern: pattern, address: addr}
	}

	entry := strings.Trim(strings.TrimSpace(line), `"'`)
	if entry == "" {
		return ruleEntry{}
	}

	if _, _, err := net.ParseCIDR(entry); err == nil {
		return ruleEntry{pattern: "IP-CIDR", address: entry}
	}
	if net.ParseIP(entry) != nil {
		return ruleEntry{pattern: "IP-CIDR", address: entry}
	}
	if after, ok0 := strings.CutPrefix(entry, "+"); ok0 {
		return ruleEntry{pattern: "DOMAIN-SUFFIX", address: strings.TrimPrefix(after, ".")}
	}
	return ruleEntry{pattern: "DOMAIN", address: entry}
}

func emitFile(ctx context.Context, resolver *asn.ASNResolver, frame *ruleFrame, sourceDir, binaryDir, name, category string) error {
	ruleSet, err := composeFile(ctx, resolver, frame)
	if err != nil {
		return err
	}
	if len(ruleSet.Rules) == 0 {
		return nil
	}

	filename := strings.ReplaceAll(name, "_", "-") + "." + category

	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	encoder := json.NewEncoder(buf)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(option.PlainRuleSetCompat{
		Version: C.RuleSetVersion4,
		Options: *ruleSet,
	}); err != nil {
		return E.Cause(err, "encode json")
	}
	if err := os.WriteFile(filepath.Join(sourceDir, filename+".json"), buf.Bytes(), filePerm); err != nil {
		return E.Cause(err, "write json")
	}

	buf.Reset()
	if err := srs.Write(buf, *ruleSet, C.RuleSetVersion4); err != nil {
		return E.Cause(err, "encode srs")
	}
	if err := os.WriteFile(filepath.Join(binaryDir, filename+".srs"), buf.Bytes(), filePerm); err != nil {
		return E.Cause(err, "write srs")
	}

	return nil
}

func composeFile(ctx context.Context, resolver *asn.ASNResolver, frame *ruleFrame) (*option.PlainRuleSet, error) {
	rules := make([]option.HeadlessRule, 0, len(frame.groups)+1)

	for _, spec := range []struct {
		key    string
		mode   string
		invert bool
	}{
		{key: "AND", mode: "and"},
		{key: "OR", mode: "or"},
		{key: "NOT", mode: "and", invert: true},
	} {
		if addrs := frame.groups[spec.key]; len(addrs) > 0 {
			logicalRules, err := singLogicalRules(ctx, resolver, addrs, spec.mode, spec.invert)
			if err != nil {
				return nil, err
			}
			rules = append(rules, logicalRules...)
		}
	}

	defaultRule := option.DefaultHeadlessRule{}

	patterns := make([]string, 0, len(frame.groups))
	for pattern := range frame.groups {
		if _, isLogical := logicalRuleKeys[pattern]; !isLogical {
			patterns = append(patterns, pattern)
		}
	}
	sort.Strings(patterns)

	for _, pattern := range patterns {
		addresses := frame.groups[pattern]
		switch pattern {
		case "DOMAIN":
			defaultRule.Domain = badoption.Listable[string](dedupe(addresses))
		case "DOMAIN-SUFFIX":
			defaultRule.DomainSuffix = badoption.Listable[string](dedupe(addresses))
		case "DOMAIN-KEYWORD":
			defaultRule.DomainKeyword = badoption.Listable[string](dedupe(addresses))
		case "DOMAIN-REGEX":
			if valid := filterValidRegex(addresses); len(valid) > 0 {
				defaultRule.DomainRegex = badoption.Listable[string](dedupe(valid))
			}
		case "DOMAIN-WILDCARD":
			if wildcardPatterns := maskWildcards(addresses); len(wildcardPatterns) > 0 {
				defaultRule.DomainRegex = badoption.Listable[string](dedupe(append([]string(defaultRule.DomainRegex), wildcardPatterns...)))
			}
		case "IP-ASN":
			if cidrList, err := resolver.ResolveASNs(ctx, normalizeASNs(addresses)); err == nil && len(cidrList) > 0 {
				defaultRule.IPCIDR = badoption.Listable[string](dedupe(append([]string(defaultRule.IPCIDR), cidrList...)))
			}
		case "SUBNET":
			for _, addr := range addresses {
				networkType, ok := parseNetworkType(addr)
				if !ok {
					continue
				}
				defaultRule.NetworkType = append(defaultRule.NetworkType, networkType)
			}
		case "IP-CIDR", "IP-CIDR6":
			defaultRule.IPCIDR = badoption.Listable[string](dedupe(append([]string(defaultRule.IPCIDR), normalizeCIDRs(addresses)...)))
		case "SRC-IP":
			defaultRule.SourceIPCIDR = badoption.Listable[string](dedupe(normalizeCIDRs(addresses)))
		case "DEST-PORT", "IN-PORT":
			ports, ranges := processPorts(addresses)
			if len(ports) > 0 {
				defaultRule.Port = badoption.Listable[uint16](ports)
			}
			if len(ranges) > 0 {
				defaultRule.PortRange = badoption.Listable[string](dedupe(ranges))
			}
		case "SRC-PORT":
			ports, ranges := processPorts(addresses)
			if len(ports) > 0 {
				defaultRule.SourcePort = badoption.Listable[uint16](ports)
			}
			if len(ranges) > 0 {
				defaultRule.SourcePortRange = badoption.Listable[string](dedupe(ranges))
			}
		case "PROCESS-NAME":
			for _, addr := range addresses {
				processRule(&defaultRule, addr)
			}
		}
	}

	defaultRule = deduplicateDefaultRule(defaultRule)
	if defaultRule.IsValid() {
		rules = append(rules, option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: defaultRule})
	}

	return &option.PlainRuleSet{Rules: rules}, nil
}

func parseNetworkType(value string) (option.InterfaceType, bool) {
	value = strings.TrimSpace(value)
	switch {
	case strings.EqualFold(value, "WIFI"):
		return option.InterfaceType(C.InterfaceTypeWIFI), true
	case strings.EqualFold(value, "WIRED"):
		return option.InterfaceType(C.InterfaceTypeEthernet), true
	case strings.EqualFold(value, "CELLULAR"):
		return option.InterfaceType(C.InterfaceTypeCellular), true
	default:
		return 0, false
	}
}

func singLogicalRules(ctx context.Context, resolver *asn.ASNResolver, addresses []string, mode string, invert bool) ([]option.HeadlessRule, error) {
	rules := make([]option.HeadlessRule, 0, len(addresses))

	for _, addr := range addresses {
		if !strings.HasPrefix(addr, "((") || !strings.HasSuffix(addr, "))") {
			continue
		}

		inner := strings.TrimSpace(addr[2 : len(addr)-2])
		if inner == "" {
			continue
		}

		parts := splitLogicalParts(inner)
		if len(parts) == 0 {
			continue
		}

		subRules := make([]option.HeadlessRule, 0, len(parts))
		for _, raw := range parts {
			stripped := strings.TrimSpace(raw)
			ruleType, ruleValue, ok := strings.Cut(stripped, ",")
			if !ok {
				continue
			}

			ruleType = strings.TrimSpace(ruleType)
			ruleValue = strings.TrimSpace(ruleValue)
			if ruleType == "" || ruleValue == "" {
				continue
			}

			if subRule := parseSingSubRule(ctx, resolver, ruleType, ruleValue); subRule != nil {
				subRules = append(subRules, *subRule)
			}
		}

		if len(subRules) > 0 {
			rules = append(rules, option.HeadlessRule{
				Type: C.RuleTypeLogical,
				LogicalOptions: option.LogicalHeadlessRule{
					Mode:   mode,
					Rules:  subRules,
					Invert: invert,
				},
			})
		}
	}

	return rules, nil
}

func splitLogicalParts(inner string) []string {
	normalized := strings.ReplaceAll(inner, "), (", "),(")
	if strings.Contains(normalized, "),(") {
		parts := strings.Split(normalized, "),(")
		for i := range parts {
			parts[i] = strings.TrimPrefix(parts[i], "(")
			parts[i] = strings.TrimSuffix(parts[i], ")")
			parts[i] = strings.TrimSpace(parts[i])
		}
		return parts
	}
	if strings.HasPrefix(normalized, "(") && strings.HasSuffix(normalized, ")") {
		return []string{strings.TrimSpace(normalized[1 : len(normalized)-1])}
	}
	return []string{strings.TrimSpace(normalized)}
}

func parseSingSubRule(ctx context.Context, resolver *asn.ASNResolver, ruleType, ruleValue string) *option.HeadlessRule {
	typeUpper := strings.ToUpper(strings.TrimSpace(ruleType))
	ruleValue = strings.TrimSpace(ruleValue)
	if typeUpper == "" || ruleValue == "" {
		return nil
	}

	rule := option.DefaultHeadlessRule{}

	switch typeUpper {
	case "DOMAIN":
		rule.Domain = badoption.Listable[string]{ruleValue}
	case "DOMAIN-SUFFIX":
		rule.DomainSuffix = badoption.Listable[string]{ruleValue}
	case "DOMAIN-KEYWORD":
		rule.DomainKeyword = badoption.Listable[string]{ruleValue}
	case "DOMAIN-WILDCARD":
		if patterns := maskWildcards([]string{ruleValue}); len(patterns) > 0 {
			rule.DomainRegex = badoption.Listable[string](patterns)
		}
	case "IP-CIDR", "IP-CIDR6":
		rule.IPCIDR = badoption.Listable[string](normalizeCIDRs([]string{ruleValue}))
	case "IP-ASN":
		asnCode := strings.ToUpper(ruleValue)
		if !strings.HasPrefix(asnCode, "AS") {
			asnCode = "AS" + asnCode
		}
		if cidrs, err := resolver.ResolveASNs(ctx, []string{asnCode}); err == nil && len(cidrs) > 0 {
			rule.IPCIDR = badoption.Listable[string](cidrs)
		}
	case "PROCESS-NAME":
		processRule(&rule, ruleValue)
	case "DEST-PORT", "IN-PORT":
		ports, ranges := processPorts([]string{ruleValue})
		if len(ports) > 0 {
			rule.Port = badoption.Listable[uint16](ports)
		}
		if len(ranges) > 0 {
			rule.PortRange = badoption.Listable[string](ranges)
		}
	case "SRC-PORT":
		ports, ranges := processPorts([]string{ruleValue})
		if len(ports) > 0 {
			rule.SourcePort = badoption.Listable[uint16](ports)
		}
		if len(ranges) > 0 {
			rule.SourcePortRange = badoption.Listable[string](ranges)
		}
	case "SRC-IP":
		rule.SourceIPCIDR = badoption.Listable[string](normalizeCIDRs([]string{ruleValue}))
	default:
		return nil
	}

	if !rule.IsValid() {
		return nil
	}

	return &option.HeadlessRule{
		Type:           C.RuleTypeDefault,
		DefaultOptions: rule,
	}
}

func processRule(rule *option.DefaultHeadlessRule, address string) {
	address = strings.TrimSpace(address)
	if address == "" {
		return
	}

	if isPathLike(address) {
		if isWildcardLike(address) {
			masked := maskRegex(address)
			if validateRegex(masked) {
				rule.ProcessPathRegex = append(rule.ProcessPathRegex, masked)
			}
			return
		}
		if isRegexLike(address) {
			rule.ProcessPathRegex = append(rule.ProcessPathRegex, address)
			return
		}
		rule.ProcessPath = append(rule.ProcessPath, address)
		return
	}

	if isRegexLike(address) {
		if prefix, company, app, options, ok := parseProcessRegexComplex(address); ok {
			rule.ProcessName = appendProcessOptions(rule.ProcessName, prefix, company, app, options)
			return
		}
		if prefix, company, options, ok := parseProcessRegexSimple(address); ok {
			rule.ProcessName = appendProcessOptionsSimple(rule.ProcessName, prefix, company, options)
			return
		}
		return
	}

	rule.ProcessName = append(rule.ProcessName, address)
}

func appendProcessOptions(existing []string, prefix, company, app, options string) []string {
	for opt := range strings.SplitSeq(options, "|") {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}
		existing = append(existing, fmt.Sprintf("%s.%s.%s.%s", prefix, company, app, opt))
	}
	return existing
}

func appendProcessOptionsSimple(existing []string, prefix, company, options string) []string {
	for opt := range strings.SplitSeq(options, "|") {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}
		existing = append(existing, fmt.Sprintf("%s.%s.%s", prefix, company, opt))
	}
	return existing
}

func parseProcessRegexComplex(value string) (prefix, company, app, options string, ok bool) {
	parts := parseProcessRegexPattern(value)
	if len(parts) != 4 {
		return "", "", "", "", false
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[3] == "" {
		return "", "", "", "", false
	}
	return parts[0], parts[1], parts[2], parts[3], true
}

func parseProcessRegexSimple(value string) (prefix, company, options string, ok bool) {
	parts := parseProcessRegexPattern(value)
	if len(parts) != 3 {
		return "", "", "", false
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func parseProcessRegexPattern(value string) []string {
	value = strings.TrimSpace(value)
	if !strings.HasSuffix(value, ")") {
		return nil
	}
	openIdx := strings.LastIndex(value, ".(")
	if openIdx <= 0 || openIdx+2 >= len(value)-1 {
		return nil
	}
	head := value[:openIdx]
	options := value[openIdx+2 : len(value)-1]
	if strings.Contains(options, ")") {
		return nil
	}
	parts := strings.Split(head, ".")
	for _, p := range parts {
		if p == "" || strings.Contains(p, "(") || strings.Contains(p, ")") {
			return nil
		}
	}
	parts = append(parts, options)
	return parts
}

func deduplicateDefaultRule(rule option.DefaultHeadlessRule) option.DefaultHeadlessRule {
	rule.Domain = badoption.Listable[string](dedupe(rule.Domain))
	rule.DomainSuffix = badoption.Listable[string](dedupe(rule.DomainSuffix))
	rule.DomainKeyword = badoption.Listable[string](dedupe(rule.DomainKeyword))
	rule.DomainRegex = badoption.Listable[string](dedupe(rule.DomainRegex))
	rule.IPCIDR = badoption.Listable[string](dedupe(rule.IPCIDR))
	rule.ProcessName = badoption.Listable[string](dedupe(rule.ProcessName))
	rule.ProcessPathRegex = badoption.Listable[string](dedupe(rule.ProcessPathRegex))
	rule.ProcessPath = badoption.Listable[string](dedupe(rule.ProcessPath))
	rule.WIFISSID = badoption.Listable[string](dedupe(rule.WIFISSID))
	rule.WIFIBSSID = badoption.Listable[string](dedupe(rule.WIFIBSSID))
	rule.PortRange = badoption.Listable[string](dedupe(rule.PortRange))
	rule.SourcePortRange = badoption.Listable[string](dedupe(rule.SourcePortRange))
	rule.SourceIPCIDR = badoption.Listable[string](dedupe(rule.SourceIPCIDR))
	rule.NetworkType = dedupeNetworkTypes(rule.NetworkType)
	rule.Port = dedupeUint16(rule.Port)
	rule.SourcePort = dedupeUint16(rule.SourcePort)
	return rule
}

func dedupeNetworkTypes(values []option.InterfaceType) []option.InterfaceType {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[option.InterfaceType]struct{}, len(values))
	out := make([]option.InterfaceType, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func validateRegex(pattern string) bool {
	if pattern == "" {
		return false
	}
	if cached, ok := regexValidationCache.Load(pattern); ok {
		return cached.(bool)
	}
	_, err := coregex.Compile(pattern)
	valid := err == nil
	regexValidationCache.Store(pattern, valid)
	return valid
}

func maskRegex(pattern string) string {
	masked := strings.TrimPrefix(pattern, ".")
	if masked == "" {
		return "^$"
	}

	quoted := regexp.QuoteMeta(masked)
	quoted = strings.ReplaceAll(quoted, `\*`, `[\w.-]*?`)
	quoted = strings.ReplaceAll(quoted, `\?`, `[\w.-]`)
	return "^" + quoted + "$"
}

func normalizeCIDR(entry string) string {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return ""
	}
	if strings.Contains(entry, "/") {
		return entry
	}

	ip := net.ParseIP(entry)
	if ip == nil {
		return entry
	}
	if ip.To4() != nil {
		return entry + "/32"
	}
	return entry + "/128"
}

func normalizeCIDRs(entries []string) []string {
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		result = append(result, normalizeCIDR(strings.TrimSuffix(entry, ",no-resolve")))
	}
	return result
}

func isRegexLike(value string) bool {
	if !strings.ContainsAny(value, `\+*?()|[]{}^$`) {
		return false
	}
	return validateRegex(value)
}

func isWildcardLike(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || !strings.ContainsAny(value, "*?") {
		return false
	}
	return doublestar.ValidatePattern(value)
}

func isPathLike(value string) bool {
	if value == "" {
		return false
	}
	if filepath.IsAbs(value) || filepath.VolumeName(value) != "" {
		return true
	}
	if strings.ContainsAny(value, `/\`) {
		return true
	}
	return path.Clean(value) != "." && strings.Contains(path.Clean(value), "/")
}

func filterValidRegex(addresses []string) []string {
	valid := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" || !validateRegex(address) {
			continue
		}
		valid = append(valid, address)
	}
	return valid
}

func maskWildcards(addresses []string) []string {
	patterns := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" {
			continue
		}
		if !doublestar.ValidatePattern(address) {
			continue
		}
		masked := maskRegex(address)
		if validateRegex(masked) {
			patterns = append(patterns, masked)
		}
	}
	return patterns
}

func dedupe[S ~[]string](items S) []string {
	if len(items) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func normalizeASNs(addresses []string) []string {
	asns := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address = strings.ToUpper(strings.TrimSpace(address))
		if address == "" {
			continue
		}
		if !strings.HasPrefix(address, "AS") {
			address = "AS" + address
		}
		asns = append(asns, address)
	}
	return asns
}

func processPorts(addresses []string) ([]uint16, []string) {
	ports := make([]uint16, 0, len(addresses))
	ranges := make([]string, 0, len(addresses))

	for _, raw := range addresses {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		if strings.ContainsAny(raw, "-:") {
			delimiter := ':'
			if strings.ContainsRune(raw, '-') {
				delimiter = '-'
			}
			if left, right, ok := strings.Cut(raw, string(delimiter)); ok {
				start64, errStart := strconv.ParseUint(strings.TrimSpace(left), 10, 16)
				end64, errEnd := strconv.ParseUint(strings.TrimSpace(right), 10, 16)
				if errStart == nil && errEnd == nil {
					start := int(start64)
					end := int(end64)
					if !isValidPort(start) || !isValidPort(end) {
						continue
					}
					if start > end {
						start, end = end, start
					}
					ranges = append(ranges, fmt.Sprintf("%d:%d", start, end))
					continue
				}
			}
		}

		port64, err := strconv.ParseUint(raw, 10, 16)
		if err != nil {
			continue
		}
		port := int(port64)
		if !isValidPort(port) {
			continue
		}
		ports = append(ports, uint16(port))
	}

	return dedupeUint16(ports), dedupe(ranges)
}

func isValidPort(port int) bool {
	return port >= 0 && port <= 65535
}

func dedupeUint16(values []uint16) []uint16 {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[uint16]struct{}, len(values))
	out := make([]uint16, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
