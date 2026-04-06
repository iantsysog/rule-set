package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
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

	"github.com/iantsysog/sing-rule/convertor/asn"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/compatible"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
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

	regexValidationCache = compatible.New[string, bool]()
)

type ruleEntry struct {
	pattern string
	address string
}

type ruleFrame struct {
	groups map[string][]string
}

type ruleFile struct {
	path     string
	category string
	name     string
}

type sourceOpener interface {
	Open(ctx context.Context, source string) (io.ReadCloser, error)
}

type httpSourceOpener struct {
	client *http.Client
}

func (o httpSourceOpener) Open(ctx context.Context, source string) (io.ReadCloser, error) {
	if after, ok := strings.CutPrefix(source, "file://"); ok {
		return os.Open(filepath.Clean(after))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, source)
	}
	return resp.Body, nil
}

type builder struct {
	resolver *asn.ASNResolver
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, unix.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		slog.Error("rule generation failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	listDir := findDirectory("List", "../List")
	if listDir == "" {
		return E.New("list directory not found")
	}

	modulesDir := findDirectory("Modules/Rules/sukka_local_dns_mapping", "../Modules/Rules/sukka_local_dns_mapping")

	startContext := adapter.NewHTTPStartContext(ctx)
	defer startContext.Close()
	client := startContext.HTTPClient("", N.SystemDialer)
	client.Timeout = httpTimeout
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.Proxy = http.ProxyFromEnvironment
		transport.TLSHandshakeTimeout = httpTimeout
		transport.ResponseHeaderTimeout = httpTimeout
		transport.ExpectContinueTimeout = httpTimeout / 2
		transport.MaxResponseHeaderBytes = 1 << 20
		transport.MaxIdleConns = maxKeepalive
		transport.MaxConnsPerHost = maxConnections
		transport.IdleConnTimeout = httpPoolTimeout
		transport.MaxIdleConnsPerHost = maxKeepalive
	}

	subdirs := []string{"domainset", "ip", "non_ip", "dns"}
	sourceDir := filepath.Join("sing-box", "go", "source")
	binaryDir := filepath.Join("sing-box", "go", "binary")

	if err := ensureDirectories(sourceDir, subdirs); err != nil {
		return E.Cause(err, "create source directories")
	}
	if err := ensureDirectories(binaryDir, subdirs); err != nil {
		return E.Cause(err, "create binary directories")
	}

	ruleFiles, err := collectFiles(listDir, []string{"domainset", "ip", "non_ip"})
	if err != nil {
		return E.Cause(err, "collect files")
	}
	if modulesDir != "" {
		dnsFiles, dnsErr := collectFiles(modulesDir, []string{"dns"})
		if dnsErr == nil {
			ruleFiles = append(ruleFiles, dnsFiles...)
		}
	}

	resolver, err := asn.NewASNResolver()
	if err != nil {
		return E.Cause(err, "create ASN resolver")
	}

	opener := httpSourceOpener{client: client}
	b := builder{resolver: resolver}

	worker, workerCtx := batch.New(ctx, batch.WithConcurrencyNum[struct{}](maxConnections))
	for _, f := range ruleFiles {
		file := f
		worker.Go(file.path, func() (struct{}, error) {
			return struct{}{}, processFile(workerCtx, opener, b, file, sourceDir, binaryDir)
		})
	}

	if batchErr := worker.Wait(); batchErr != nil {
		return batchErr
	}
	return nil
}

func processFile(ctx context.Context, opener sourceOpener, b builder, file ruleFile, sourceDir, binaryDir string) error {
	frame, err := prepareFrame(ctx, opener, "file://"+file.path)
	if err != nil || frame == nil {
		return err
	}

	sourcePath := filepath.Join(sourceDir, file.category)
	binaryPath := filepath.Join(binaryDir, file.category)
	return emitFile(ctx, b, frame, sourcePath, binaryPath, file.name, file.category)
}

func findDirectory(paths ...string) string {
	for _, p := range paths {
		p = os.ExpandEnv(p)
		if rw.IsDir(p) {
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

func collectFiles(dir string, categories []string) ([]ruleFile, error) {
	files := make([]ruleFile, 0, 64)

	for _, category := range categories {
		searchDir := filepath.Join(dir, category)
		if category == "dns" {
			searchDir = dir
		}

		entries, err := os.ReadDir(searchDir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if filepath.Ext(name) != ".conf" {
				continue
			}
			base := strings.TrimSuffix(name, ".conf")
			if base == "" {
				continue
			}
			files = append(files, ruleFile{
				path:     filepath.Join(searchDir, name),
				category: category,
				name:     base,
			})
		}
	}

	sort.Slice(files, func(i, j int) bool {
		a, b := files[i], files[j]
		if a.category != b.category {
			return a.category < b.category
		}
		if a.name != b.name {
			return a.name < b.name
		}
		return a.path < b.path
	})

	return files, nil
}

func prepareFrame(ctx context.Context, opener sourceOpener, source string) (*ruleFrame, error) {
	reader, err := opener.Open(ctx, source)
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
	scanner.Buffer((*bufPtr)[:0], scannerMaxSize)

	lines := make([]string, 0, 256)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	groups := collectFrameGroups(lines)
	if len(groups) == 0 {
		return nil, nil
	}

	return &ruleFrame{groups: groups}, nil
}

func collectFrameGroups(lines []string) map[string][]string {
	groups := make(map[string][]string, len(lines))
	seen := make(map[ruleEntry]struct{}, len(lines))

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}

		entry := parseRuleLine(line)
		if entry.pattern == "" || entry.address == "" || strings.Contains(entry.pattern, "#") {
			continue
		}
		if _, excluded := excludedAddresses[entry.address]; excluded {
			continue
		}
		if _, exists := seen[entry]; exists {
			continue
		}
		seen[entry] = struct{}{}
		groups[entry.pattern] = append(groups[entry.pattern], entry.address)
	}

	return groups
}

func parseRuleLine(line string) ruleEntry {
	if pattern, rest, ok := strings.Cut(line, ","); ok {
		pattern = strings.TrimSpace(pattern)
		rest = strings.TrimSpace(rest)
		if pattern == "" || rest == "" {
			return ruleEntry{}
		}

		if addr, suffix, hasSuffix := strings.Cut(rest, ","); hasSuffix {
			addr = strings.TrimSpace(addr)
			suffix = strings.TrimSpace(suffix)
			if addr == "" {
				return ruleEntry{}
			}
			if suffix == "" {
				return ruleEntry{pattern: pattern, address: addr}
			}
			return ruleEntry{pattern: pattern, address: addr + "," + suffix}
		}

		return ruleEntry{pattern: pattern, address: strings.TrimSpace(rest)}
	}

	entry := strings.Trim(strings.TrimSpace(line), `"'`)
	if entry == "" {
		return ruleEntry{}
	}

	if _, err := netip.ParsePrefix(entry); err == nil {
		return ruleEntry{pattern: "IP-CIDR", address: entry}
	}
	if M.ParseAddr(entry).IsValid() {
		return ruleEntry{pattern: "IP-CIDR", address: entry}
	}
	if after, ok := strings.CutPrefix(entry, "+"); ok {
		return ruleEntry{pattern: "DOMAIN-SUFFIX", address: strings.TrimPrefix(after, ".")}
	}
	return ruleEntry{pattern: "DOMAIN", address: entry}
}

func emitFile(ctx context.Context, b builder, frame *ruleFrame, sourceDir, binaryDir, name, category string) error {
	ruleSet, err := b.buildRuleSet(ctx, frame)
	if err != nil {
		return err
	}
	if len(ruleSet.Rules) == 0 {
		return nil
	}

	if err := validateRuleSet(ctx, name, ruleSet); err != nil {
		return E.Cause(err, "validate rule-set")
	}

	filename := strings.ReplaceAll(name, "_", "-") + "." + category

	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	encoder := json.NewEncoder(buf)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(option.PlainRuleSetCompat{Version: C.RuleSetVersionCurrent, Options: *ruleSet}); err != nil {
		return E.Cause(err, "encode json")
	}
	if err := writeFileIfChanged(filepath.Join(sourceDir, filename+".json"), buf.Bytes(), filePerm); err != nil {
		return E.Cause(err, "write json")
	}

	buf.Reset()
	if err := srs.Write(buf, *ruleSet, C.RuleSetVersionCurrent); err != nil {
		return E.Cause(err, "encode srs")
	}
	if err := writeFileIfChanged(filepath.Join(binaryDir, filename+".srs"), buf.Bytes(), filePerm); err != nil {
		return E.Cause(err, "write srs")
	}

	return nil
}

func validateRuleSet(ctx context.Context, name string, ruleSet *option.PlainRuleSet) error {
	for i, ruleOptions := range ruleSet.Rules {
		_, err := R.NewHeadlessRule(ctx, ruleOptions)
		if err != nil {
			return E.Cause(err, fmt.Sprintf("validate rule set %q rule #%d", name, i))
		}
	}
	return nil
}

func (b builder) buildRuleSet(ctx context.Context, frame *ruleFrame) (*option.PlainRuleSet, error) {
	rules := make([]option.HeadlessRule, 0, len(frame.groups)+1)

	for _, spec := range [...]struct {
		key    string
		mode   string
		invert bool
	}{
		{key: "AND", mode: C.LogicalTypeAnd},
		{key: "OR", mode: C.LogicalTypeOr},
		{key: "NOT", mode: C.LogicalTypeAnd, invert: true},
	} {
		if addrs := frame.groups[spec.key]; len(addrs) > 0 {
			logicalRules, err := buildLogicalRules(ctx, b.resolver, addrs, spec.mode, spec.invert)
			if err != nil {
				return nil, err
			}
			rules = append(rules, logicalRules...)
		}
	}

	defaultRule := option.DefaultHeadlessRule{}

	patterns := make([]string, 0, len(frame.groups))
	for pattern := range frame.groups {
		switch pattern {
		case "AND", "OR", "NOT":
			continue
		default:
			patterns = append(patterns, pattern)
		}
	}
	sort.Strings(patterns)

	for _, pattern := range patterns {
		addresses := frame.groups[pattern]
		switch pattern {
		case "DOMAIN":
			setStringList(&defaultRule.Domain, addresses)
		case "DOMAIN-SUFFIX":
			setStringList(&defaultRule.DomainSuffix, addresses)
		case "DOMAIN-KEYWORD":
			setStringList(&defaultRule.DomainKeyword, addresses)
		case "DOMAIN-REGEX":
			setStringList(&defaultRule.DomainRegex, filterValidRegex(addresses))
		case "DOMAIN-WILDCARD":
			mergeIntoStringList(&defaultRule.DomainRegex, maskWildcards(addresses))
		case "IP-ASN":
			if b.resolver != nil {
				if cidrList, err := b.resolver.ResolveASNs(ctx, normalizeASNs(addresses)); err == nil {
					mergeIntoStringList(&defaultRule.IPCIDR, cidrList)
				}
			}
		case "SUBNET":
			for _, addr := range addresses {
				networkType, ok := parseNetworkType(addr)
				if ok {
					defaultRule.NetworkType = append(defaultRule.NetworkType, networkType)
				}
			}
		case "IP-CIDR", "IP-CIDR6":
			mergeIntoStringList(&defaultRule.IPCIDR, normalizeCIDRs(addresses))
		case "SRC-IP":
			setStringList(&defaultRule.SourceIPCIDR, normalizeCIDRs(addresses))
		case "DEST-PORT", "IN-PORT":
			ports, ranges := processPorts(addresses)
			if len(ports) > 0 {
				defaultRule.Port = badoption.Listable[uint16](ports)
			}
			setStringList(&defaultRule.PortRange, ranges)
		case "SRC-PORT":
			ports, ranges := processPorts(addresses)
			if len(ports) > 0 {
				defaultRule.SourcePort = badoption.Listable[uint16](ports)
			}
			setStringList(&defaultRule.SourcePortRange, ranges)
		case "PROCESS-NAME":
			for _, addr := range addresses {
				processRule(&defaultRule, addr)
			}
		case "PROTOCOL":
			protocols := make([]string, 0, len(addresses))
			for _, addr := range addresses {
				addrUpper := strings.ToUpper(strings.TrimSpace(addr))
				if addrUpper == "TCP" || addrUpper == "UDP" {
					protocols = append(protocols, strings.ToLower(addrUpper))
				}
			}
			if len(protocols) > 0 {
				setStringList(&defaultRule.Network, protocols)
			}
		}
	}

	setStringList(&defaultRule.Domain, defaultRule.Domain)
	setStringList(&defaultRule.DomainSuffix, defaultRule.DomainSuffix)
	setStringList(&defaultRule.DomainKeyword, defaultRule.DomainKeyword)
	setStringList(&defaultRule.DomainRegex, defaultRule.DomainRegex)
	setStringList(&defaultRule.IPCIDR, defaultRule.IPCIDR)
	setStringList(&defaultRule.ProcessName, defaultRule.ProcessName)
	setStringList(&defaultRule.ProcessPathRegex, defaultRule.ProcessPathRegex)
	setStringList(&defaultRule.ProcessPath, defaultRule.ProcessPath)
	setStringList(&defaultRule.WIFISSID, defaultRule.WIFISSID)
	setStringList(&defaultRule.WIFIBSSID, defaultRule.WIFIBSSID)
	setStringList(&defaultRule.PortRange, defaultRule.PortRange)
	setStringList(&defaultRule.SourcePortRange, defaultRule.SourcePortRange)
	setStringList(&defaultRule.SourceIPCIDR, defaultRule.SourceIPCIDR)
	defaultRule.NetworkType = common.Uniq(defaultRule.NetworkType)
	defaultRule.Port = common.Uniq(defaultRule.Port)
	defaultRule.SourcePort = common.Uniq(defaultRule.SourcePort)
	if defaultRule.IsValid() {
		rules = append(rules, option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: defaultRule})
	}

	return &option.PlainRuleSet{Rules: rules}, nil
}

func setStringList(dst *badoption.Listable[string], values []string) {
	filtered := common.FilterNotDefault(values)
	if len(filtered) == 0 {
		*dst = nil
		return
	}
	*dst = badoption.Listable[string](common.Uniq(filtered))
}

func mergeIntoStringList(dst *badoption.Listable[string], add []string) {
	if len(add) == 0 {
		return
	}
	merged := make([]string, 0, len(*dst)+len(add))
	merged = append(merged, (*dst)...)
	merged = append(merged, add...)
	setStringList(dst, merged)
}

func parseNetworkType(value string) (option.InterfaceType, bool) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return 0, false
	}
	switch normalized {
	case "wired":
		normalized = "ethernet"
	}
	iface, ok := C.StringToInterfaceType[normalized]
	if !ok {
		return 0, false
	}
	return option.InterfaceType(iface), true
}

func buildLogicalRules(ctx context.Context, resolver *asn.ASNResolver, addresses []string, mode string, invert bool) ([]option.HeadlessRule, error) {
	rules := make([]option.HeadlessRule, 0, len(addresses))

	for _, addr := range addresses {
		if !strings.HasPrefix(addr, "((") || !strings.HasSuffix(addr, "))") {
			continue
		}

		inner := strings.TrimSpace(addr[1 : len(addr)-1])
		if inner == "" {
			continue
		}

		parts := splitLogicalParts(inner)
		if len(parts) == 0 {
			continue
		}

		subRules := make([]option.HeadlessRule, 0, len(parts))
		for _, raw := range parts {
			ruleType, ruleValue, ok := strings.Cut(strings.TrimSpace(raw), ",")
			if !ok {
				continue
			}
			ruleType = strings.TrimSpace(ruleType)
			ruleValue = strings.TrimSpace(ruleValue)
			if ruleType == "" || ruleValue == "" {
				continue
			}

			if subRule := parseLogicalSubRule(ctx, resolver, ruleType, ruleValue); subRule != nil {
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
	inner = strings.TrimSpace(inner)
	if inner == "" {
		return nil
	}

	parts := make([]string, 0, 4)
	start, depth := 0, 0

	for i := range len(inner) {
		switch inner[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				part := strings.TrimSpace(inner[start:i])
				part = unwrapOuterParentheses(part)
				if part != "" {
					parts = append(parts, part)
				}
				start = i + 1
			}
		}
	}

	tail := strings.TrimSpace(inner[start:])
	tail = unwrapOuterParentheses(tail)
	if tail != "" {
		parts = append(parts, tail)
	}

	return parts
}

func unwrapOuterParentheses(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '(' || value[len(value)-1] != ')' {
		return value
	}

	depth := 0
	for i := range len(value) {
		switch value[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && i != len(value)-1 {
				return value
			}
		}
	}
	if depth != 0 {
		return value
	}

	return strings.TrimSpace(value[1 : len(value)-1])
}

func parseLogicalSubRule(ctx context.Context, resolver *asn.ASNResolver, ruleType, ruleValue string) *option.HeadlessRule {
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
		if resolver != nil {
			asnCode := strings.ToUpper(ruleValue)
			if !strings.HasPrefix(asnCode, "AS") {
				asnCode = "AS" + asnCode
			}
			if cidrs, err := resolver.ResolveASNs(ctx, []string{asnCode}); err == nil && len(cidrs) > 0 {
				rule.IPCIDR = badoption.Listable[string](cidrs)
			}
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
	case "PROTOCOL":
		ruleValueUpper := strings.ToUpper(ruleValue)
		if ruleValueUpper == "TCP" || ruleValueUpper == "UDP" {
			rule.Network = badoption.Listable[string]{strings.ToLower(ruleValueUpper)}
		}
	default:
		return nil
	}

	if !rule.IsValid() {
		return nil
	}

	return &option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: rule}
}

func processRule(rule *option.DefaultHeadlessRule, address string) {
	address = strings.TrimSpace(address)
	if address == "" {
		return
	}

	isPath := isPathLike(address)
	if masked, ok := processPattern(address, isPath); ok {
		rule.ProcessPathRegex = append(rule.ProcessPathRegex, masked)
		return
	}
	if isPath {
		rule.ProcessPath = append(rule.ProcessPath, address)
		return
	}
	rule.ProcessName = append(rule.ProcessName, address)
}

func processPattern(address string, isPath bool) (string, bool) {
	if isWildcardLike(address) {
		masked := maskPathRegex(address)
		return masked, validateRegex(masked)
	}
	if isRegexLike(address) {
		return address, true
	}
	return "", false
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
				start, errStart := parsePort(left)
				end, errEnd := parsePort(right)
				if errStart == nil && errEnd == nil {
					if start > end {
						start, end = end, start
					}
					ranges = append(ranges, fmt.Sprintf("%d:%d", start, end))
					continue
				}
			}
		}

		port, err := parsePort(raw)
		if err == nil {
			ports = append(ports, port)
		}
	}

	ranges = common.FilterNotDefault(ranges)
	if len(ranges) == 0 {
		return common.Uniq(ports), nil
	}
	return common.Uniq(ports), common.Uniq(ranges)
}

func validateRegex(pattern string) bool {
	if pattern == "" {
		return false
	}
	if cached, ok := regexValidationCache.Load(pattern); ok {
		return cached
	}
	_, err := regexp.Compile(pattern)
	valid := err == nil
	regexValidationCache.Store(pattern, valid)
	return valid
}

func wildcardPatternToRegex(pattern string) string {
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

	if prefix, err := netip.ParsePrefix(entry); err == nil {
		return prefix.String()
	}
	addr := M.ParseAddr(entry)
	if !addr.IsValid() {
		return ""
	}
	if addr.Is4() {
		return addr.String() + "/32"
	}
	return addr.String() + "/128"
}

func normalizeCIDRs(entries []string) []string {
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		normalized := normalizeCIDR(strings.TrimSuffix(strings.TrimSpace(entry), ",no-resolve"))
		if normalized != "" {
			result = append(result, normalized)
		}
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
	asns = common.FilterNotDefault(asns)
	if len(asns) == 0 {
		return nil
	}
	return common.Uniq(asns)
}

func isRegexLike(value string) bool {
	if !strings.ContainsAny(value, `\+*?()|[]{}^$`) {
		return false
	}
	return validateRegex(value)
}

func isWildcardLike(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && strings.ContainsAny(value, "*?")
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
	cleaned := path.Clean(value)
	return cleaned != "." && strings.Contains(cleaned, "/")
}

func filterValidRegex(addresses []string) []string {
	valid := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address != "" && validateRegex(address) {
			valid = append(valid, address)
		}
	}
	return valid
}

func maskPathRegex(pattern string) string {
	masked := strings.TrimSpace(pattern)
	if masked == "" {
		return "^$"
	}

	quoted := regexp.QuoteMeta(masked)
	quoted = strings.ReplaceAll(quoted, `\*`, `.*?`)
	quoted = strings.ReplaceAll(quoted, `\?`, `.`)
	return "^" + quoted + "$"
}

func maskWildcards(addresses []string) []string {
	patterns := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" || !isWildcardLike(address) {
			continue
		}
		masked := wildcardPatternToRegex(address)
		if validateRegex(masked) {
			patterns = append(patterns, masked)
		}
	}
	return patterns
}

func parsePort(raw string) (uint16, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 16)
	if err != nil || v == 0 {
		return 0, strconv.ErrSyntax
	}
	return uint16(v), nil
}

func writeFileIfChanged(path string, content []byte, perm os.FileMode) error {
	current, err := os.ReadFile(path)
	if err == nil && bytes.Equal(current, content) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(path, content, perm)
}
