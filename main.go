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
	"slices"
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

type RuleKind string

const (
	RuleKindUnknown        RuleKind = ""
	RuleKindDomain         RuleKind = "DOMAIN"
	RuleKindDomainSuffix   RuleKind = "DOMAIN-SUFFIX"
	RuleKindDomainKeyword  RuleKind = "DOMAIN-KEYWORD"
	RuleKindDomainRegex    RuleKind = "DOMAIN-REGEX"
	RuleKindDomainWildcard RuleKind = "DOMAIN-WILDCARD"
	RuleKindIPASN          RuleKind = "IP-ASN"
	RuleKindIPCIDR         RuleKind = "IP-CIDR"
	RuleKindIPCIDR6        RuleKind = "IP-CIDR6"
	RuleKindSourceIP       RuleKind = "SRC-IP"
	RuleKindDestPort       RuleKind = "DEST-PORT"
	RuleKindInPort         RuleKind = "IN-PORT"
	RuleKindSourcePort     RuleKind = "SRC-PORT"
	RuleKindProcessName    RuleKind = "PROCESS-NAME"
	RuleKindProtocol       RuleKind = "PROTOCOL"
	RuleKindSubnet         RuleKind = "SUBNET"
	RuleKindLogicalAnd     RuleKind = "AND"
	RuleKindLogicalOr      RuleKind = "OR"
	RuleKindLogicalNot     RuleKind = "NOT"
)

type ruleEntry struct {
	kind    RuleKind
	address string
}

type ruleFrame struct {
	groups map[RuleKind][]string
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

type ruleHandler func(
	ctx context.Context,
	resolver *asn.ASNResolver,
	acc *ruleAccumulator,
	addresses []string,
)

type ruleAccumulator struct {
	rule option.DefaultHeadlessRule
}

type logicalRuleSpec struct {
	kind   RuleKind
	mode   string
	invert bool
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

func collectFrameGroups(lines []string) map[RuleKind][]string {
	groups := make(map[RuleKind][]string, len(lines))
	seen := make(map[ruleEntry]struct{}, len(lines))

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}

		entry := parseRuleLine(line)
		if entry.kind == RuleKindUnknown || entry.address == "" {
			continue
		}

		if isExcludedAddress(entry.address) {
			continue
		}

		if _, exists := seen[entry]; exists {
			continue
		}

		seen[entry] = struct{}{}
		groups[entry.kind] = append(groups[entry.kind], entry.address)
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

	kind, ok := parseRuleKind(strings.TrimSpace(pattern))
	if !ok {
		return ruleEntry{}, true
	}

	address := joinRuleAddress(rest)
	if address == "" {
		return ruleEntry{}, true
	}

	return ruleEntry{kind: kind, address: address}, true
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
		return ruleEntry{kind: RuleKindIPCIDR, address: entry}
	}

	if after, ok := strings.CutPrefix(entry, "+"); ok {
		return ruleEntry{kind: RuleKindDomainSuffix, address: strings.TrimPrefix(after, ".")}
	}

	return ruleEntry{kind: RuleKindDomain, address: entry}
}

func parseRuleKind(raw string) (RuleKind, bool) {
	normalized := strings.ToUpper(strings.TrimSpace(raw))

	kind, ok := map[string]RuleKind{
		string(RuleKindDomain):         RuleKindDomain,
		string(RuleKindDomainSuffix):   RuleKindDomainSuffix,
		string(RuleKindDomainKeyword):  RuleKindDomainKeyword,
		string(RuleKindDomainRegex):    RuleKindDomainRegex,
		string(RuleKindDomainWildcard): RuleKindDomainWildcard,
		string(RuleKindIPASN):          RuleKindIPASN,
		string(RuleKindIPCIDR):         RuleKindIPCIDR,
		string(RuleKindIPCIDR6):        RuleKindIPCIDR6,
		string(RuleKindSourceIP):       RuleKindSourceIP,
		string(RuleKindDestPort):       RuleKindDestPort,
		string(RuleKindInPort):         RuleKindInPort,
		string(RuleKindSourcePort):     RuleKindSourcePort,
		string(RuleKindProcessName):    RuleKindProcessName,
		string(RuleKindProtocol):       RuleKindProtocol,
		string(RuleKindSubnet):         RuleKindSubnet,
		string(RuleKindLogicalAnd):     RuleKindLogicalAnd,
		string(RuleKindLogicalOr):      RuleKindLogicalOr,
		string(RuleKindLogicalNot):     RuleKindLogicalNot,
	}[normalized]
	if !ok {
		return RuleKindUnknown, false
	}

	return kind, true
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
	groups map[RuleKind][]string,
) []option.HeadlessRule {
	rules := make([]option.HeadlessRule, 0, len(groups))
	for _, spec := range logicalRuleSpecs() {
		addresses := groups[spec.kind]
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
	groups map[RuleKind][]string,
) option.DefaultHeadlessRule {
	acc := newRuleAccumulator()
	for _, kind := range sortedDefaultKinds(groups) {
		acc.apply(ctx, b.resolver, kind, groups[kind])
	}

	return acc.export()
}

func newRuleAccumulator() *ruleAccumulator {
	return &ruleAccumulator{}
}

func (a *ruleAccumulator) apply(
	ctx context.Context,
	resolver *asn.ASNResolver,
	kind RuleKind,
	addresses []string,
) bool {
	handler, ok := ruleHandlerRegistry()[kind]
	if !ok {
		return false
	}

	handler(ctx, resolver, a, addresses)

	return true
}

func (a *ruleAccumulator) export() option.DefaultHeadlessRule {
	finalizeDefaultRule(&a.rule)

	return a.rule
}

func logicalRuleSpecs() []logicalRuleSpec {
	return []logicalRuleSpec{
		{kind: RuleKindLogicalAnd, mode: C.LogicalTypeAnd},
		{kind: RuleKindLogicalOr, mode: C.LogicalTypeOr},
		{kind: RuleKindLogicalNot, mode: C.LogicalTypeAnd, invert: true},
	}
}

func sortedDefaultKinds(groups map[RuleKind][]string) []RuleKind {
	kinds := make([]RuleKind, 0, len(groups))
	for kind := range groups {
		if isLogicalKind(kind) {
			continue
		}

		kinds = append(kinds, kind)
	}

	slices.Sort(kinds)

	return kinds
}

func isLogicalKind(kind RuleKind) bool {
	return kind == RuleKindLogicalAnd || kind == RuleKindLogicalOr || kind == RuleKindLogicalNot
}

func ruleHandlerRegistry() map[RuleKind]ruleHandler {
	return map[RuleKind]ruleHandler{
		RuleKindDomain:         applyDomainRule,
		RuleKindDomainSuffix:   applyDomainSuffixRule,
		RuleKindDomainKeyword:  applyDomainKeywordRule,
		RuleKindDomainRegex:    applyDomainRegexRule,
		RuleKindDomainWildcard: applyDomainWildcardRule,
		RuleKindIPASN:          applyIPASNRule,
		RuleKindIPCIDR:         applyIPCIDRRule,
		RuleKindIPCIDR6:        applyIPCIDRRule,
		RuleKindSourceIP:       applySourceIPRule,
		RuleKindDestPort:       applyDestPortRule,
		RuleKindInPort:         applyDestPortRule,
		RuleKindSourcePort:     applySourcePortRule,
		RuleKindProcessName:    applyProcessNameRule,
		RuleKindProtocol:       applyProtocolRule,
		RuleKindSubnet:         applySubnetRule,
	}
}

func applyDomainRule(
	_ context.Context,
	_ *asn.ASNResolver,
	acc *ruleAccumulator,
	addresses []string,
) {
	setStringList(&acc.rule.Domain, addresses)
}

func applyDomainSuffixRule(
	_ context.Context,
	_ *asn.ASNResolver,
	acc *ruleAccumulator,
	addresses []string,
) {
	setStringList(&acc.rule.DomainSuffix, addresses)
}

func applyDomainKeywordRule(
	_ context.Context,
	_ *asn.ASNResolver,
	acc *ruleAccumulator,
	addresses []string,
) {
	setStringList(&acc.rule.DomainKeyword, addresses)
}

func applyDomainRegexRule(
	_ context.Context,
	_ *asn.ASNResolver,
	acc *ruleAccumulator,
	addresses []string,
) {
	setStringList(&acc.rule.DomainRegex, filterValidRegex(addresses))
}

func applyDomainWildcardRule(
	_ context.Context,
	_ *asn.ASNResolver,
	acc *ruleAccumulator,
	addresses []string,
) {
	mergeIntoStringList(&acc.rule.DomainRegex, maskWildcards(addresses))
}

func applyIPASNRule(
	ctx context.Context,
	resolver *asn.ASNResolver,
	acc *ruleAccumulator,
	addresses []string,
) {
	if resolver == nil {
		return
	}

	cidrList, err := resolver.ResolveASNs(ctx, normalizeASNs(addresses))
	if err == nil {
		mergeIntoStringList(&acc.rule.IPCIDR, cidrList)
	}
}

func applyIPCIDRRule(
	_ context.Context,
	_ *asn.ASNResolver,
	acc *ruleAccumulator,
	addresses []string,
) {
	mergeIntoStringList(&acc.rule.IPCIDR, normalizeCIDRs(addresses))
}

func applySourceIPRule(
	_ context.Context,
	_ *asn.ASNResolver,
	acc *ruleAccumulator,
	addresses []string,
) {
	setStringList(&acc.rule.SourceIPCIDR, normalizeCIDRs(addresses))
}

func applyDestPortRule(
	_ context.Context,
	_ *asn.ASNResolver,
	acc *ruleAccumulator,
	addresses []string,
) {
	ports, ranges := processPorts(addresses)
	if len(ports) > 0 {
		acc.rule.Port = badoption.Listable[uint16](ports)
	}

	setStringList(&acc.rule.PortRange, ranges)
}

func applySourcePortRule(
	_ context.Context,
	_ *asn.ASNResolver,
	acc *ruleAccumulator,
	addresses []string,
) {
	ports, ranges := processPorts(addresses)
	if len(ports) > 0 {
		acc.rule.SourcePort = badoption.Listable[uint16](ports)
	}

	setStringList(&acc.rule.SourcePortRange, ranges)
}

func applyProcessNameRule(
	_ context.Context,
	_ *asn.ASNResolver,
	acc *ruleAccumulator,
	addresses []string,
) {
	for _, addr := range addresses {
		processRule(&acc.rule, addr)
	}
}

func applyProtocolRule(
	_ context.Context,
	_ *asn.ASNResolver,
	acc *ruleAccumulator,
	addresses []string,
) {
	setStringList(&acc.rule.Network, normalizeProtocols(addresses))
}

func applySubnetRule(
	_ context.Context,
	_ *asn.ASNResolver,
	acc *ruleAccumulator,
	addresses []string,
) {
	for _, addr := range addresses {
		networkType, ok := parseNetworkType(addr)
		if ok {
			acc.rule.NetworkType = append(acc.rule.NetworkType, networkType)
		}
	}
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

	parts := splitLogicalParts(inner)

	subRules := make([]option.HeadlessRule, 0, len(parts))
	for _, raw := range parts {
		entry := parseLogicalPart(raw)
		if subRule := parseLogicalSubRule(ctx, resolver, entry); subRule != nil {
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

func parseLogicalPart(raw string) ruleEntry {
	entry := parseRuleLine(strings.TrimSpace(raw))
	if isLogicalKind(entry.kind) {
		return ruleEntry{}
	}

	return entry
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
	entry ruleEntry,
) *option.HeadlessRule {
	if entry.kind == RuleKindUnknown || entry.address == "" {
		return nil
	}

	acc := newRuleAccumulator()
	if !acc.apply(ctx, resolver, entry.kind, []string{entry.address}) {
		return nil
	}

	rule := acc.export()
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
