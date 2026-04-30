package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	"time"

	"github.com/iantsysog/sing-rule/convertor/asn"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/rw"
	"golang.org/x/sys/unix"
)

const (
	httpTimeout                          = 10 * time.Second
	httpPoolTimeout                      = 30 * time.Second
	maxConnections                       = 100
	maxKeepalive                         = 20
	scannerBufSize                       = 64 * 1024
	scannerMaxSize                       = 1024 * 1024
	filePerm                             = 0o644
	dirPerm                              = 0o755
	expectContinueDivisor                = 2
	maxHTTPHeaderBytes                   = 1 << 20
	initialRuleFilesCap                  = 64
	initialFrameLinesCap                 = 256
	initialLogicalPartsCap               = 4
	errUnexpectedHTTPStatus  staticError = "unexpected HTTP status"
	errListDirectoryNotFound staticError = "list directory not found"
	errEmptyRuleFrame        staticError = "empty rule frame"
)

type staticError string

func (e staticError) Error() string {
	return string(e)
}

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
		reader, err := os.Open(filepath.Clean(after))
		if err != nil {
			return nil, fmt.Errorf("open source file %q: %w", after, err)
		}

		return reader, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %q: %w", source, err)
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch source %q: %w", source, err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()

		return nil, fmt.Errorf("%w %d from %s", errUnexpectedHTTPStatus, resp.StatusCode, source)
	}

	return resp.Body, nil
}

type builder struct {
	resolver *asn.ASNResolver
}

type resettableHTTPTransport struct {
	*http.Transport
}

func (t *resettableHTTPTransport) Reset() {
	t.CloseIdleConnections()
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, unix.SIGTERM)
	err := run(ctx)

	cancel()

	if err != nil {
		slog.Error("rule generation failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	listDir := findDirectory("List", "../List")
	if listDir == "" {
		return fmt.Errorf("run rule generation: %w", errListDirectoryNotFound)
	}

	modulesDir := findDirectory(
		"Modules/Rules/sukka_local_dns_mapping",
		"../Modules/Rules/sukka_local_dns_mapping",
	)

	startContext := adapter.NewHTTPStartContext()
	defer startContext.Close()

	transport := &resettableHTTPTransport{Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			return N.SystemDialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
		},
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    httpTimeout,
		ResponseHeaderTimeout:  httpTimeout,
		ExpectContinueTimeout:  httpTimeout / expectContinueDivisor,
		MaxResponseHeaderBytes: maxHTTPHeaderBytes,
		MaxIdleConns:           maxKeepalive,
		MaxConnsPerHost:        maxConnections,
		IdleConnTimeout:        httpPoolTimeout,
		MaxIdleConnsPerHost:    maxKeepalive,
		TLSClientConfig: &tls.Config{
			Time:    ntp.TimeFuncFromContext(ctx),
			RootCAs: adapter.RootPoolFromContext(ctx),
		},
	}}
	startContext.Register(transport)
	client := &http.Client{
		Transport: transport,
		Timeout:   httpTimeout,
	}

	subdirs := []string{"domainset", "ip", "non_ip", "dns"}
	sourceDir := filepath.Join("sing-box", "go", "source")
	binaryDir := filepath.Join("sing-box", "go", "binary")

	err := ensureDirectories(sourceDir, subdirs)
	if err != nil {
		return fmt.Errorf("create source directories: %w", err)
	}

	err = ensureDirectories(binaryDir, subdirs)
	if err != nil {
		return fmt.Errorf("create binary directories: %w", err)
	}

	ruleFiles, err := collectFiles(listDir, []string{"domainset", "ip", "non_ip"})
	if err != nil {
		return fmt.Errorf("collect files: %w", err)
	}

	if modulesDir != "" {
		dnsFiles, dnsErr := collectFiles(modulesDir, []string{"dns"})
		if dnsErr == nil {
			ruleFiles = append(ruleFiles, dnsFiles...)
		}
	}

	resolver, err := asn.NewASNResolver()
	if err != nil {
		return fmt.Errorf("create ASN resolver: %w", err)
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

	batchErr := worker.Wait()
	if batchErr != nil {
		return batchErr
	}

	return nil
}

func processFile(
	ctx context.Context,
	opener sourceOpener,
	b builder,
	file ruleFile,
	sourceDir, binaryDir string,
) error {
	frame, err := prepareFrame(ctx, opener, "file://"+file.path)
	if err != nil {
		if errors.Is(err, errEmptyRuleFrame) {
			return nil
		}

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
		err := os.MkdirAll(filepath.Join(baseDir, sub), dirPerm)
		if err != nil {
			return fmt.Errorf("create directory %q: %w", filepath.Join(baseDir, sub), err)
		}
	}

	return nil
}

func collectFiles(dir string, categories []string) ([]ruleFile, error) {
	files := make([]ruleFile, 0, initialRuleFilesCap)

	for _, category := range categories {
		categoryFiles, err := collectCategoryFiles(dir, category)
		if err != nil {
			return nil, err
		}

		files = append(files, categoryFiles...)
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

func collectCategoryFiles(dir string, category string) ([]ruleFile, error) {
	searchDir := categoryDirectory(dir, category)

	entries, err := os.ReadDir(searchDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []ruleFile{}, nil
		}

		return nil, fmt.Errorf("read category directory %q: %w", searchDir, err)
	}

	files := make([]ruleFile, 0, len(entries))
	for _, entry := range entries {
		file, ok := newRuleFile(searchDir, category, entry)
		if ok {
			files = append(files, file)
		}
	}

	return files, nil
}

func categoryDirectory(dir string, category string) string {
	if category == "dns" {
		return dir
	}

	return filepath.Join(dir, category)
}

func newRuleFile(searchDir, category string, entry os.DirEntry) (ruleFile, bool) {
	if entry.IsDir() {
		return ruleFile{}, false
	}

	name := entry.Name()
	if filepath.Ext(name) != ".conf" {
		return ruleFile{}, false
	}

	base := strings.TrimSuffix(name, ".conf")
	if base == "" {
		return ruleFile{}, false
	}

	return ruleFile{
		path:     filepath.Join(searchDir, name),
		category: category,
		name:     base,
	}, true
}

func prepareFrame(ctx context.Context, opener sourceOpener, source string) (*ruleFrame, error) {
	reader, err := opener.Open(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("open frame source %q: %w", source, err)
	}

	if reader == nil {
		return nil, fmt.Errorf("open frame source %q: %w", source, errEmptyRuleFrame)
	}

	defer func() { _ = reader.Close() }()

	scannerBuf := make([]byte, scannerBufSize)

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(scannerBuf[:0], scannerMaxSize)

	lines := make([]string, 0, initialFrameLinesCap)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("scan frame source %q: %w", source, err)
	}

	groups := collectFrameGroups(lines)
	if len(groups) == 0 {
		return nil, fmt.Errorf("parse frame source %q: %w", source, errEmptyRuleFrame)
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

		if isExcludedAddress(entry.address) {
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
	if entry, ok := parseExplicitRuleLine(line); ok {
		return entry
	}

	return parseImplicitRuleLine(line)
}

func parseExplicitRuleLine(line string) (ruleEntry, bool) {
	pattern, rest, ok := strings.Cut(line, ",")
	if !ok {
		return ruleEntry{}, false
	}

	pattern = strings.TrimSpace(pattern)

	address := joinRuleAddress(rest)
	if pattern == "" || address == "" {
		return ruleEntry{}, true
	}

	return ruleEntry{pattern: pattern, address: address}, true
}

func joinRuleAddress(rest string) string {
	parts := strings.Split(rest, ",")

	trimmed := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			break
		}

		trimmed = append(trimmed, part)
	}

	return strings.Join(trimmed, ",")
}

func parseImplicitRuleLine(line string) ruleEntry {
	entry := strings.Trim(strings.TrimSpace(line), `"'`)
	if entry == "" {
		return ruleEntry{}
	}

	if isCIDREntry(entry) {
		return ruleEntry{pattern: "IP-CIDR", address: entry}
	}

	if after, ok := strings.CutPrefix(entry, "+"); ok {
		return ruleEntry{pattern: "DOMAIN-SUFFIX", address: strings.TrimPrefix(after, ".")}
	}

	return ruleEntry{pattern: "DOMAIN", address: entry}
}

func isCIDREntry(entry string) bool {
	_, err := netip.ParsePrefix(entry)
	if err == nil {
		return true
	}

	return M.ParseAddr(entry).IsValid()
}

func isExcludedAddress(address string) bool {
	switch address {
	case "",
		"#",
		"th1s_rule5et_1s_m4d3_by_5ukk4w_ruleset.skk.moe",
		"7h1s_rul35et_i5_mad3_by_5ukk4w-ruleset.skk.moe":
		return true
	default:
		return false
	}
}

func emitFile(
	ctx context.Context,
	b builder,
	frame *ruleFrame,
	sourceDir, binaryDir, name, category string,
) error {
	ruleSet := b.buildRuleSet(ctx, frame)

	if len(ruleSet.Rules) == 0 {
		return nil
	}

	err := validateRuleSet(ctx, name, ruleSet)
	if err != nil {
		return fmt.Errorf("validate rule-set: %w", err)
	}

	filename := strings.ReplaceAll(name, "_", "-") + "." + category

	buf := bytes.NewBuffer(nil)

	encoder := json.NewEncoder(buf)
	encoder.SetIndent("", "  ")

	err = encoder.Encode(
		option.PlainRuleSetCompat{Version: C.RuleSetVersionCurrent, Options: *ruleSet},
	)
	if err != nil {
		return fmt.Errorf("encode json: %w", err)
	}

	err = writeFileIfChanged(
		filepath.Join(sourceDir, filename+".json"),
		buf.Bytes(),
		filePerm,
	)
	if err != nil {
		return fmt.Errorf("write json: %w", err)
	}

	buf.Reset()

	err = srs.Write(buf, *ruleSet, C.RuleSetVersionCurrent)
	if err != nil {
		return fmt.Errorf("encode srs: %w", err)
	}

	err = writeFileIfChanged(
		filepath.Join(binaryDir, filename+".srs"),
		buf.Bytes(),
		filePerm,
	)
	if err != nil {
		return fmt.Errorf("write srs: %w", err)
	}

	return nil
}

func validateRuleSet(ctx context.Context, name string, ruleSet *option.PlainRuleSet) error {
	for i, ruleOptions := range ruleSet.Rules {
		_, err := R.NewHeadlessRule(ctx, ruleOptions)
		if err != nil {
			return fmt.Errorf("validate rule set %q rule #%d: %w", name, i, err)
		}
	}

	return nil
}

func (b builder) buildRuleSet(ctx context.Context, frame *ruleFrame) *option.PlainRuleSet {
	rules := b.buildLogicalHeadlessRules(ctx, frame.groups)
	defaultRule := b.buildDefaultRule(ctx, frame.groups)

	finalizeDefaultRule(&defaultRule)

	if defaultRule.IsValid() {
		rules = append(rules, option.HeadlessRule{
			Type:           C.RuleTypeDefault,
			DefaultOptions: defaultRule,
		})
	}

	return &option.PlainRuleSet{Rules: rules}
}

func (b builder) buildLogicalHeadlessRules(
	ctx context.Context,
	groups map[string][]string,
) []option.HeadlessRule {
	rules := make([]option.HeadlessRule, 0, len(groups))
	for _, spec := range logicalRuleSpecs() {
		addresses := groups[spec.key]
		if len(addresses) == 0 {
			continue
		}

		logicalRules := buildLogicalRules(ctx, b.resolver, addresses, spec.mode, spec.invert)
		rules = append(rules, logicalRules...)
	}

	return rules
}

func (b builder) buildDefaultRule(
	ctx context.Context,
	groups map[string][]string,
) option.DefaultHeadlessRule {
	defaultRule := option.DefaultHeadlessRule{}
	for _, pattern := range sortedDefaultPatterns(groups) {
		b.applyDefaultPattern(ctx, &defaultRule, pattern, groups[pattern])
	}

	return defaultRule
}

func (b builder) applyDefaultPattern(
	ctx context.Context,
	defaultRule *option.DefaultHeadlessRule,
	pattern string,
	addresses []string,
) {
	if applyStringPattern(defaultRule, pattern, addresses) {
		return
	}

	if applyIPPattern(ctx, b.resolver, defaultRule, pattern, addresses) {
		return
	}

	if applyPortPattern(defaultRule, pattern, addresses) {
		return
	}

	applyAttributePattern(defaultRule, pattern, addresses)
}

func logicalRuleSpecs() []struct {
	key    string
	mode   string
	invert bool
} {
	return []struct {
		key    string
		mode   string
		invert bool
	}{
		{key: "AND", mode: C.LogicalTypeAnd},
		{key: "OR", mode: C.LogicalTypeOr},
		{key: "NOT", mode: C.LogicalTypeAnd, invert: true},
	}
}

func sortedDefaultPatterns(groups map[string][]string) []string {
	patterns := make([]string, 0, len(groups))
	for pattern := range groups {
		if isLogicalPattern(pattern) {
			continue
		}

		patterns = append(patterns, pattern)
	}

	sort.Strings(patterns)

	return patterns
}

func isLogicalPattern(pattern string) bool {
	switch pattern {
	case "AND", "OR", "NOT":
		return true
	default:
		return false
	}
}

func applyStringPattern(rule *option.DefaultHeadlessRule, pattern string, addresses []string) bool {
	switch pattern {
	case "DOMAIN":
		setStringList(&rule.Domain, addresses)
	case "DOMAIN-SUFFIX":
		setStringList(&rule.DomainSuffix, addresses)
	case "DOMAIN-KEYWORD":
		setStringList(&rule.DomainKeyword, addresses)
	case "DOMAIN-REGEX":
		setStringList(&rule.DomainRegex, filterValidRegex(addresses))
	case "DOMAIN-WILDCARD":
		mergeIntoStringList(&rule.DomainRegex, maskWildcards(addresses))
	default:
		return false
	}

	return true
}

func applyIPPattern(
	ctx context.Context,
	resolver *asn.ASNResolver,
	rule *option.DefaultHeadlessRule,
	pattern string,
	addresses []string,
) bool {
	switch pattern {
	case "IP-ASN":
		if resolver == nil {
			return true
		}

		cidrList, err := resolver.ResolveASNs(ctx, normalizeASNs(addresses))
		if err == nil {
			mergeIntoStringList(&rule.IPCIDR, cidrList)
		}
	case "IP-CIDR", "IP-CIDR6":
		mergeIntoStringList(&rule.IPCIDR, normalizeCIDRs(addresses))
	case "SRC-IP":
		setStringList(&rule.SourceIPCIDR, normalizeCIDRs(addresses))
	default:
		return false
	}

	return true
}

func applyPortPattern(rule *option.DefaultHeadlessRule, pattern string, addresses []string) bool {
	ports, ranges := processPorts(addresses)

	switch pattern {
	case "DEST-PORT", "IN-PORT":
		if len(ports) > 0 {
			rule.Port = badoption.Listable[uint16](ports)
		}

		setStringList(&rule.PortRange, ranges)
	case "SRC-PORT":
		if len(ports) > 0 {
			rule.SourcePort = badoption.Listable[uint16](ports)
		}

		setStringList(&rule.SourcePortRange, ranges)
	default:
		return false
	}

	return true
}

func applyAttributePattern(
	rule *option.DefaultHeadlessRule,
	pattern string,
	addresses []string,
) bool {
	switch pattern {
	case "SUBNET":
		for _, addr := range addresses {
			networkType, ok := parseNetworkType(addr)
			if ok {
				rule.NetworkType = append(rule.NetworkType, networkType)
			}
		}
	case "PROCESS-NAME":
		for _, addr := range addresses {
			processRule(rule, addr)
		}
	case "PROTOCOL":
		setStringList(&rule.Network, normalizeProtocols(addresses))
	default:
		return false
	}

	return true
}

func normalizeProtocols(addresses []string) []string {
	protocols := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		addrUpper := strings.ToUpper(strings.TrimSpace(addr))
		if addrUpper == "TCP" || addrUpper == "UDP" {
			protocols = append(protocols, strings.ToLower(addrUpper))
		}
	}

	return protocols
}

func finalizeDefaultRule(defaultRule *option.DefaultHeadlessRule) {
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

	if normalized == "wired" {
		normalized = "ethernet"
	}

	iface, ok := C.StringToInterfaceType[normalized]
	if !ok {
		return 0, false
	}

	return option.InterfaceType(iface), true
}

func buildLogicalRules(
	ctx context.Context,
	resolver *asn.ASNResolver,
	addresses []string,
	mode string,
	invert bool,
) []option.HeadlessRule {
	rules := make([]option.HeadlessRule, 0, len(addresses))

	for _, addr := range addresses {
		subRules := parseLogicalRuleGroup(ctx, resolver, addr)
		if len(subRules) > 0 {
			rules = append(rules, newLogicalHeadlessRule(subRules, mode, invert))
		}
	}

	return rules
}

func splitLogicalParts(inner string) []string {
	inner = strings.TrimSpace(inner)
	if inner == "" {
		return nil
	}

	parts := make([]string, 0, initialLogicalPartsCap)
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

func parseLogicalRuleGroup(
	ctx context.Context,
	resolver *asn.ASNResolver,
	address string,
) []option.HeadlessRule {
	inner, ok := logicalGroupBody(address)
	if !ok {
		return nil
	}

	subRules := make([]option.HeadlessRule, 0, len(inner))
	for _, raw := range splitLogicalParts(inner) {
		ruleType, ruleValue, ok := parseLogicalPart(raw)
		if !ok {
			continue
		}

		if subRule := parseLogicalSubRule(ctx, resolver, ruleType, ruleValue); subRule != nil {
			subRules = append(subRules, *subRule)
		}
	}

	return subRules
}

func logicalGroupBody(address string) (string, bool) {
	if !strings.HasPrefix(address, "((") || !strings.HasSuffix(address, "))") {
		return "", false
	}

	inner := strings.TrimSpace(address[1 : len(address)-1])

	return inner, inner != ""
}

func parseLogicalPart(raw string) (string, string, bool) {
	ruleType, ruleValue, ok := strings.Cut(strings.TrimSpace(raw), ",")
	if !ok {
		return "", "", false
	}

	ruleType = strings.TrimSpace(ruleType)
	ruleValue = strings.TrimSpace(ruleValue)

	if ruleType == "" || ruleValue == "" {
		return "", "", false
	}

	return ruleType, ruleValue, true
}

func newLogicalHeadlessRule(
	subRules []option.HeadlessRule,
	mode string,
	invert bool,
) option.HeadlessRule {
	return option.HeadlessRule{
		Type: C.RuleTypeLogical,
		LogicalOptions: option.LogicalHeadlessRule{
			Mode:   mode,
			Rules:  subRules,
			Invert: invert,
		},
	}
}

func parseLogicalSubRule(
	ctx context.Context,
	resolver *asn.ASNResolver,
	ruleType, ruleValue string,
) *option.HeadlessRule {
	typeUpper := strings.ToUpper(strings.TrimSpace(ruleType))

	ruleValue = strings.TrimSpace(ruleValue)
	if typeUpper == "" || ruleValue == "" {
		return nil
	}

	rule, ok := buildLogicalDomainRule(typeUpper, ruleValue)
	if !ok {
		rule, ok = buildLogicalIPRule(ctx, resolver, typeUpper, ruleValue)
	}

	if !ok {
		rule, ok = buildLogicalPortRule(typeUpper, ruleValue)
	}

	if !ok {
		rule, ok = buildLogicalAttributeRule(typeUpper, ruleValue)
	}

	if !ok || !rule.IsValid() {
		return nil
	}

	return &option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: rule}
}

func buildLogicalDomainRule(ruleType, ruleValue string) (option.DefaultHeadlessRule, bool) {
	switch ruleType {
	case "DOMAIN":
		return option.DefaultHeadlessRule{
			Domain: badoption.Listable[string]{ruleValue},
		}, true
	case "DOMAIN-SUFFIX":
		return option.DefaultHeadlessRule{
			DomainSuffix: badoption.Listable[string]{ruleValue},
		}, true
	case "DOMAIN-KEYWORD":
		return option.DefaultHeadlessRule{
			DomainKeyword: badoption.Listable[string]{ruleValue},
		}, true
	case "DOMAIN-WILDCARD":
		patterns := maskWildcards([]string{ruleValue})
		if len(patterns) == 0 {
			return option.DefaultHeadlessRule{}, false
		}

		return option.DefaultHeadlessRule{
			DomainRegex: badoption.Listable[string](patterns),
		}, true
	default:
		return option.DefaultHeadlessRule{}, false
	}
}

func buildLogicalIPRule(
	ctx context.Context,
	resolver *asn.ASNResolver,
	ruleType, ruleValue string,
) (option.DefaultHeadlessRule, bool) {
	switch ruleType {
	case "IP-CIDR", "IP-CIDR6":
		return option.DefaultHeadlessRule{
			IPCIDR: badoption.Listable[string](normalizeCIDRs([]string{ruleValue})),
		}, true
	case "IP-ASN":
		cidrs := resolveLogicalASN(ctx, resolver, ruleValue)
		if len(cidrs) == 0 {
			return option.DefaultHeadlessRule{}, false
		}

		return option.DefaultHeadlessRule{
			IPCIDR: badoption.Listable[string](cidrs),
		}, true
	case "SRC-IP":
		return option.DefaultHeadlessRule{
			SourceIPCIDR: badoption.Listable[string](normalizeCIDRs([]string{ruleValue})),
		}, true
	default:
		return option.DefaultHeadlessRule{}, false
	}
}

func resolveLogicalASN(
	ctx context.Context,
	resolver *asn.ASNResolver,
	ruleValue string,
) []string {
	if resolver == nil {
		return nil
	}

	cidrs, err := resolver.ResolveASNs(ctx, normalizeASNs([]string{ruleValue}))
	if err != nil {
		return nil
	}

	return cidrs
}

func buildLogicalPortRule(ruleType, ruleValue string) (option.DefaultHeadlessRule, bool) {
	ports, ranges := processPorts([]string{ruleValue})

	switch ruleType {
	case "DEST-PORT", "IN-PORT":
		return option.DefaultHeadlessRule{
			Port:      badoption.Listable[uint16](ports),
			PortRange: badoption.Listable[string](ranges),
		}, true
	case "SRC-PORT":
		return option.DefaultHeadlessRule{
			SourcePort:      badoption.Listable[uint16](ports),
			SourcePortRange: badoption.Listable[string](ranges),
		}, true
	default:
		return option.DefaultHeadlessRule{}, false
	}
}

func buildLogicalAttributeRule(ruleType, ruleValue string) (option.DefaultHeadlessRule, bool) {
	switch ruleType {
	case "PROCESS-NAME":
		rule := option.DefaultHeadlessRule{}
		processRule(&rule, ruleValue)

		return rule, true
	case "PROTOCOL":
		protocols := normalizeProtocols([]string{ruleValue})
		if len(protocols) == 0 {
			return option.DefaultHeadlessRule{}, false
		}

		return option.DefaultHeadlessRule{
			Network: badoption.Listable[string](protocols),
		}, true
	default:
		return option.DefaultHeadlessRule{}, false
	}
}

func processRule(rule *option.DefaultHeadlessRule, address string) {
	address = strings.TrimSpace(address)
	if address == "" {
		return
	}

	isPath := isPathLike(address)
	if masked, ok := processPattern(address); ok {
		rule.ProcessPathRegex = append(rule.ProcessPathRegex, masked)

		return
	}

	if isPath {
		rule.ProcessPath = append(rule.ProcessPath, address)

		return
	}

	rule.ProcessName = append(rule.ProcessName, address)
}

func processPattern(address string) (string, bool) {
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

		if portRange, ok := parsePortRange(raw); ok {
			ranges = append(ranges, portRange)

			continue
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

	_, err := regexp.Compile(pattern)

	return err == nil
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

	prefix, err := netip.ParsePrefix(entry)
	if err == nil {
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

func parsePortRange(raw string) (string, bool) {
	delimiter := portRangeDelimiter(raw)
	if delimiter == "" {
		return "", false
	}

	left, right, ok := strings.Cut(raw, delimiter)
	if !ok {
		return "", false
	}

	start, errStart := parsePort(left)

	end, errEnd := parsePort(right)
	if errStart != nil || errEnd != nil {
		return "", false
	}

	if start > end {
		start, end = end, start
	}

	return fmt.Sprintf("%d:%d", start, end), true
}

func portRangeDelimiter(raw string) string {
	switch {
	case strings.ContainsRune(raw, '-'):
		return "-"
	case strings.ContainsRune(raw, ':'):
		return ":"
	default:
		return ""
	}
}

func parsePort(raw string) (uint16, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 16)
	if err != nil || v == 0 {
		return 0, strconv.ErrSyntax
	}

	return uint16(v), nil
}

func writeFileIfChanged(path string, content []byte, perm os.FileMode) error {
	cleanedPath := filepath.Clean(path)

	current, err := os.ReadFile(cleanedPath)
	if err == nil && bytes.Equal(current, content) {
		return nil
	}

	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read current file %q: %w", cleanedPath, err)
	}

	err = os.WriteFile(cleanedPath, content, perm)
	if err != nil {
		return fmt.Errorf("write file %q: %w", cleanedPath, err)
	}

	return nil
}
