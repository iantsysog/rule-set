package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	"golang.org/x/sys/unix"
)

const (
	httpTimeout            = 10 * time.Second
	httpPoolTimeout        = 30 * time.Second
	maxConnections         = 100
	maxKeepalive           = 20
	scannerBufSize         = 64 * 1024
	scannerMaxSize         = 1024 * 1024
	filePerm               = 0o644
	dirPerm                = 0o755
	expectContinueDivisor  = 2
	maxHTTPHeaderBytes     = 1 << 20
	initialRuleFilesCap    = 64
	initialFrameLinesCap   = 256
	initialLogicalPartsCap = 4

	categoryDomainSet = "domainset"
	categoryIP        = "ip"
	categoryNonIP     = "non_ip"
	categoryDNS       = "dns"
)

var (
	errListDirectoryNotFound = errors.New("list directory not found")
	errEmptyRuleFrame        = errors.New("empty rule frame")
	errUnexpectedHTTPStatus  = errors.New("unexpected HTTP status")
)

type RuleKind string

const (
	RuleKindUnknown        RuleKind = ""
	RuleKindDomain         RuleKind = "DOMAIN"
	RuleKindDomainSuffix   RuleKind = "DOMAIN-SUFFIX"
	RuleKindDomainKeyword  RuleKind = "DOMAIN-KEYWORD"
	RuleKindDomainRegex    RuleKind = "DOMAIN-REGEX"
	RuleKindDomainWildcard RuleKind = "DOMAIN-WILDCARD"
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

func (k RuleKind) IsLogical() bool {
	return k == RuleKindLogicalAnd || k == RuleKindLogicalOr || k == RuleKindLogicalNot
}

type RuleEntry struct {
	kind    RuleKind
	address string
}

type RuleFrame struct {
	groups map[RuleKind][]string
}

type RuleFile struct {
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

type fileSystem interface {
	ReadDir(name string) ([]fs.DirEntry, error)
	MkdirAll(path string, perm fs.FileMode) error
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte, perm fs.FileMode) error
	IsDir(path string) bool
}

type osFileSystem struct{}

func (osFileSystem) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := os.ReadDir(name)
	if err != nil {
		return nil, fmt.Errorf("read dir %q: %w", name, err)
	}

	return entries, nil
}

func (osFileSystem) MkdirAll(path string, perm fs.FileMode) error {
	err := os.MkdirAll(path, perm)
	if err != nil {
		return fmt.Errorf("mkdir all %q: %w", path, err)
	}

	return nil
}

func (osFileSystem) ReadFile(name string) ([]byte, error) {
	content, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", name, err)
	}

	return content, nil
}

func (osFileSystem) WriteFile(name string, data []byte, perm fs.FileMode) error {
	err := os.WriteFile(name, data, perm)
	if err != nil {
		return fmt.Errorf("write file %q: %w", name, err)
	}

	return nil
}

func (osFileSystem) IsDir(path string) bool {
	info, err := os.Stat(path)

	return err == nil && info.IsDir()
}

type ruleSerializer interface {
	WriteJSON(w io.Writer, ruleSet *option.PlainRuleSet) error
	WriteSRS(w io.Writer, ruleSet option.PlainRuleSet) error
	Validate(ctx context.Context, name string, ruleSet *option.PlainRuleSet) error
}

type singBoxSerializer struct{}

func (singBoxSerializer) WriteJSON(w io.Writer, ruleSet *option.PlainRuleSet) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	compat := option.PlainRuleSetCompat{
		Version: C.RuleSetVersionCurrent,
		Options: *ruleSet,
	}

	err := encoder.Encode(compat)
	if err != nil {
		return fmt.Errorf("encode json: %w", err)
	}

	return nil
}

func (singBoxSerializer) WriteSRS(w io.Writer, ruleSet option.PlainRuleSet) error {
	err := srs.Write(w, ruleSet, C.RuleSetVersionCurrent)
	if err != nil {
		return fmt.Errorf("encode srs: %w", err)
	}

	return nil
}

func (singBoxSerializer) Validate(
	ctx context.Context,
	name string,
	ruleSet *option.PlainRuleSet,
) error {
	for i, ruleOptions := range ruleSet.Rules {
		_, err := R.NewHeadlessRule(ctx, ruleOptions)
		if err != nil {
			return fmt.Errorf("validate rule set %q rule #%d: %w", name, i, err)
		}
	}

	return nil
}

type resettableHTTPTransport struct {
	*http.Transport
}

func (t *resettableHTTPTransport) Reset() {
	t.CloseIdleConnections()
}

type ruleAccumulator struct {
	rule option.DefaultHeadlessRule
}

func newRuleAccumulator() *ruleAccumulator {
	return &ruleAccumulator{}
}

func (a *ruleAccumulator) apply(_ context.Context, kind RuleKind, addresses []string) bool {
	handler, ok := ruleHandlerFor(kind)
	if !ok {
		return false
	}

	handler(a, addresses)

	return true
}

func (a *ruleAccumulator) export() option.DefaultHeadlessRule {
	finalizeDefaultRule(&a.rule)

	return a.rule
}

type ruleHandler func(*ruleAccumulator, []string)

func ruleHandlerFor(kind RuleKind) (ruleHandler, bool) {
	handlers := map[RuleKind]ruleHandler{
		RuleKindDomain:         applyDomain,
		RuleKindDomainSuffix:   applyDomainSuffix,
		RuleKindDomainKeyword:  applyDomainKeyword,
		RuleKindDomainRegex:    applyDomainRegex,
		RuleKindDomainWildcard: applyDomainWildcard,
		RuleKindIPCIDR:         applyIPCIDR,
		RuleKindIPCIDR6:        applyIPCIDR,
		RuleKindSourceIP:       applySourceIP,
		RuleKindDestPort:       applyDestPort,
		RuleKindInPort:         applyDestPort,
		RuleKindSourcePort:     applySourcePort,
		RuleKindProcessName:    applyProcessName,
		RuleKindProtocol:       applyProtocol,
		RuleKindSubnet:         applySubnet,
	}

	handler, ok := handlers[kind]

	return handler, ok
}

func applyDomain(acc *ruleAccumulator, addresses []string) {
	setStrings(&acc.rule.Domain, addresses)
}

func applyDomainSuffix(acc *ruleAccumulator, addresses []string) {
	setStrings(&acc.rule.DomainSuffix, addresses)
}

func applyDomainKeyword(acc *ruleAccumulator, addresses []string) {
	setStrings(&acc.rule.DomainKeyword, addresses)
}

func applyDomainRegex(acc *ruleAccumulator, addresses []string) {
	setStrings(&acc.rule.DomainRegex, filterValidRegex(addresses))
}

func applyDomainWildcard(acc *ruleAccumulator, addresses []string) {
	mergeStrings(&acc.rule.DomainRegex, maskWildcards(addresses))
}

func applyIPCIDR(acc *ruleAccumulator, addresses []string) {
	mergeStrings(&acc.rule.IPCIDR, normalizeCIDRs(addresses))
}

func applySourceIP(acc *ruleAccumulator, addresses []string) {
	setStrings(&acc.rule.SourceIPCIDR, normalizeCIDRs(addresses))
}

func applyDestPort(acc *ruleAccumulator, addresses []string) {
	applyPortFields(&acc.rule.Port, &acc.rule.PortRange, addresses)
}

func applySourcePort(acc *ruleAccumulator, addresses []string) {
	applyPortFields(&acc.rule.SourcePort, &acc.rule.SourcePortRange, addresses)
}

func applyPortFields(
	port *badoption.Listable[uint16],
	ranges *badoption.Listable[string],
	addresses []string,
) {
	ports, rng := processPorts(addresses)
	if len(ports) > 0 {
		*port = badoption.Listable[uint16](ports)
	}

	setStrings(ranges, rng)
}

func applyProcessName(acc *ruleAccumulator, addresses []string) {
	for _, addr := range addresses {
		kind, value := classifyProcess(addr)
		switch kind {
		case processMatchName:
			acc.rule.ProcessName = append(acc.rule.ProcessName, value)
		case processMatchPath:
			acc.rule.ProcessPath = append(acc.rule.ProcessPath, value)
		case processMatchPathRegex:
			acc.rule.ProcessPathRegex = append(acc.rule.ProcessPathRegex, value)
		case processMatchNone:
		}
	}
}

func applyProtocol(acc *ruleAccumulator, addresses []string) {
	setStrings(&acc.rule.Network, normalizeProtocols(addresses))
}

func applySubnet(acc *ruleAccumulator, addresses []string) {
	for _, addr := range addresses {
		if networkType, ok := parseNetworkType(addr); ok {
			acc.rule.NetworkType = append(acc.rule.NetworkType, networkType)
		}
	}
}

type processMatchKind int

const (
	processMatchNone processMatchKind = iota
	processMatchName
	processMatchPath
	processMatchPathRegex
)

func classifyProcess(address string) (processMatchKind, string) {
	address = strings.TrimSpace(address)
	if address == "" {
		return processMatchNone, ""
	}

	isPath := isPathLike(address)
	if masked, ok := processPattern(address); ok {
		return processMatchPathRegex, masked
	}

	if isPath {
		return processMatchPath, address
	}

	return processMatchName, address
}

func finalizeDefaultRule(defaultRule *option.DefaultHeadlessRule) {
	setStrings(&defaultRule.Domain, defaultRule.Domain)
	setStrings(&defaultRule.DomainSuffix, defaultRule.DomainSuffix)
	setStrings(&defaultRule.DomainKeyword, defaultRule.DomainKeyword)
	setStrings(&defaultRule.DomainRegex, defaultRule.DomainRegex)
	setStrings(&defaultRule.IPCIDR, defaultRule.IPCIDR)
	setStrings(&defaultRule.ProcessName, defaultRule.ProcessName)
	setStrings(&defaultRule.ProcessPathRegex, defaultRule.ProcessPathRegex)
	setStrings(&defaultRule.ProcessPath, defaultRule.ProcessPath)
	setStrings(&defaultRule.WIFISSID, defaultRule.WIFISSID)
	setStrings(&defaultRule.WIFIBSSID, defaultRule.WIFIBSSID)
	setStrings(&defaultRule.PortRange, defaultRule.PortRange)
	setStrings(&defaultRule.SourcePortRange, defaultRule.SourcePortRange)
	setStrings(&defaultRule.SourceIPCIDR, defaultRule.SourceIPCIDR)
	defaultRule.NetworkType = common.Uniq(defaultRule.NetworkType)
	defaultRule.Port = common.Uniq(defaultRule.Port)
	defaultRule.SourcePort = common.Uniq(defaultRule.SourcePort)
}

func setStrings(dst *badoption.Listable[string], values []string) {
	filtered := common.FilterNotDefault(values)
	if len(filtered) == 0 {
		*dst = nil

		return
	}

	*dst = badoption.Listable[string](common.Uniq(filtered))
}

func mergeStrings(dst *badoption.Listable[string], add []string) {
	if len(add) == 0 {
		return
	}

	merged := make([]string, 0, len(*dst)+len(add))
	merged = append(merged, (*dst)...)
	merged = append(merged, add...)
	setStrings(dst, merged)
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

func parseFrame(ctx context.Context, opener sourceOpener, source string) (*RuleFrame, error) {
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

	return &RuleFrame{groups: groups}, nil
}

func collectFrameGroups(lines []string) map[RuleKind][]string {
	groups := make(map[RuleKind][]string, len(lines))
	seen := make(map[RuleEntry]struct{}, len(lines))

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

func parseRuleLine(line string) RuleEntry {
	if entry, ok := parseExplicitRuleLine(line); ok {
		return entry
	}

	return parseImplicitRuleLine(line)
}

func parseExplicitRuleLine(line string) (RuleEntry, bool) {
	pattern, rest, ok := strings.Cut(line, ",")
	if !ok {
		return RuleEntry{}, false
	}

	kind, ok := parseRuleKind(strings.TrimSpace(pattern))
	if !ok {
		return RuleEntry{}, true
	}

	address := joinRuleAddress(rest)
	if address == "" {
		return RuleEntry{}, true
	}

	return RuleEntry{kind: kind, address: address}, true
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

func parseImplicitRuleLine(line string) RuleEntry {
	entry := strings.Trim(strings.TrimSpace(line), `"'`)
	if entry == "" {
		return RuleEntry{}
	}

	if isCIDREntry(entry) {
		return RuleEntry{kind: RuleKindIPCIDR, address: entry}
	}

	if after, ok := strings.CutPrefix(entry, "+"); ok {
		return RuleEntry{kind: RuleKindDomainSuffix, address: strings.TrimPrefix(after, ".")}
	}

	return RuleEntry{kind: RuleKindDomain, address: entry}
}

func parseRuleKind(raw string) (RuleKind, bool) {
	normalized := strings.ToUpper(strings.TrimSpace(raw))
	kind, ok := map[string]RuleKind{
		string(RuleKindDomain):         RuleKindDomain,
		string(RuleKindDomainSuffix):   RuleKindDomainSuffix,
		string(RuleKindDomainKeyword):  RuleKindDomainKeyword,
		string(RuleKindDomainRegex):    RuleKindDomainRegex,
		string(RuleKindDomainWildcard): RuleKindDomainWildcard,
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

	return kind, ok
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

func buildRuleSet(ctx context.Context, frame *RuleFrame) *option.PlainRuleSet {
	rules := buildLogicalHeadlessRules(ctx, frame)
	defaultRule := buildDefaultRule(ctx, frame)

	if defaultRule.IsValid() {
		rules = append(rules, option.HeadlessRule{
			Type:           C.RuleTypeDefault,
			DefaultOptions: defaultRule,
		})
	}

	return &option.PlainRuleSet{Rules: rules}
}

func buildLogicalHeadlessRules(ctx context.Context, frame *RuleFrame) []option.HeadlessRule {
	rules := make([]option.HeadlessRule, 0, len(frame.groups))
	for _, spec := range logicalRuleSpecs() {
		addresses := frame.groups[spec.kind]
		if len(addresses) == 0 {
			continue
		}

		logicalRules := buildLogicalRules(ctx, addresses, spec.mode, spec.invert)
		rules = append(rules, logicalRules...)
	}

	return rules
}

func buildDefaultRule(ctx context.Context, frame *RuleFrame) option.DefaultHeadlessRule {
	acc := newRuleAccumulator()
	for _, kind := range sortedDefaultKinds(frame.groups) {
		acc.apply(ctx, kind, frame.groups[kind])
	}

	return acc.export()
}

type logicalRuleSpec struct {
	kind   RuleKind
	mode   string
	invert bool
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
		if kind.IsLogical() {
			continue
		}

		kinds = append(kinds, kind)
	}

	slices.Sort(kinds)

	return kinds
}

func buildLogicalRules(
	ctx context.Context,
	addresses []string,
	mode string,
	invert bool,
) []option.HeadlessRule {
	rules := make([]option.HeadlessRule, 0, len(addresses))
	for _, addr := range addresses {
		subRules := parseLogicalRuleGroup(ctx, addr)
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

func parseLogicalRuleGroup(ctx context.Context, address string) []option.HeadlessRule {
	inner, ok := logicalGroupBody(address)
	if !ok {
		return nil
	}

	parts := splitLogicalParts(inner)

	subRules := make([]option.HeadlessRule, 0, len(parts))
	for _, raw := range parts {
		entry := parseLogicalPart(raw)
		if subRule := parseLogicalSubRule(ctx, entry); subRule != nil {
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

func parseLogicalPart(raw string) RuleEntry {
	entry := parseRuleLine(strings.TrimSpace(raw))
	if entry.kind.IsLogical() {
		return RuleEntry{}
	}

	return entry
}

func parseLogicalSubRule(ctx context.Context, entry RuleEntry) *option.HeadlessRule {
	if entry.kind == RuleKindUnknown || entry.address == "" {
		return nil
	}

	acc := newRuleAccumulator()
	if !acc.apply(ctx, entry.kind, []string{entry.address}) {
		return nil
	}

	rule := acc.export()
	if !rule.IsValid() {
		return nil
	}

	return &option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: rule}
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

	return common.Uniq(valid)
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

	return common.Uniq(patterns)
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

type pipeline struct {
	fs         fileSystem
	provider   sourceOpener
	serializer ruleSerializer
}

func newPipeline(fs fileSystem, provider sourceOpener, serializer ruleSerializer) *pipeline {
	return &pipeline{
		fs:         fs,
		provider:   provider,
		serializer: serializer,
	}
}

func (p *pipeline) run(ctx context.Context, sourceDir, binaryDir string) error {
	listDir := p.findDirectory("List", "../List")
	if listDir == "" {
		return errListDirectoryNotFound
	}

	modulesDir := p.findDirectory(
		"Modules/Rules/sukka_local_dns_mapping",
		"../Modules/Rules/sukka_local_dns_mapping",
	)

	err := p.ensureDirectories(sourceDir, binaryDir)
	if err != nil {
		return err
	}

	ruleFiles, err := p.collectFiles(
		listDir,
		[]string{categoryDomainSet, categoryIP, categoryNonIP},
	)
	if err != nil {
		return fmt.Errorf("collect files: %w", err)
	}

	if modulesDir != "" {
		dnsFiles, err := p.collectFiles(modulesDir, []string{categoryDNS})
		if err == nil {
			ruleFiles = append(ruleFiles, dnsFiles...)
		}
	}

	worker, workerCtx := batch.New(ctx, batch.WithConcurrencyNum[struct{}](maxConnections))

	for _, f := range ruleFiles {
		file := f
		worker.Go(file.path, func() (struct{}, error) {
			return struct{}{}, p.processFile(workerCtx, file, sourceDir, binaryDir)
		})
	}

	waitErr := worker.Wait()
	if waitErr != nil {
		return fmt.Errorf("wait for workers: %w", waitErr)
	}

	return nil
}

func (p *pipeline) processFile(
	ctx context.Context,
	file RuleFile,
	sourceDir, binaryDir string,
) error {
	frame, err := parseFrame(ctx, p.provider, "file://"+file.path)
	if err != nil {
		if errors.Is(err, errEmptyRuleFrame) {
			return nil
		}

		return err
	}

	return p.emitFile(ctx, frame, sourceDir, binaryDir, file.name, file.category)
}

func (p *pipeline) emitFile(
	ctx context.Context,
	frame *RuleFrame,
	sourceDir, binaryDir, name, category string,
) error {
	ruleSet := buildRuleSet(ctx, frame)
	if len(ruleSet.Rules) == 0 {
		return nil
	}

	err := p.serializer.Validate(ctx, name, ruleSet)
	if err != nil {
		return fmt.Errorf("validate rule-set: %w", err)
	}

	filename := strings.ReplaceAll(name, "_", "-") + "." + category
	sourcePath := filepath.Join(sourceDir, category, filename+".json")
	binaryPath := filepath.Join(binaryDir, category, filename+".srs")

	err = p.writeSerialized(
		sourcePath,
		func(w io.Writer) error { return p.serializer.WriteJSON(w, ruleSet) },
		"json",
	)
	if err != nil {
		return err
	}

	err = p.writeSerialized(
		binaryPath,
		func(w io.Writer) error { return p.serializer.WriteSRS(w, *ruleSet) },
		"srs",
	)
	if err != nil {
		return err
	}

	return nil
}

func (p *pipeline) writeSerialized(path string, encode func(io.Writer) error, format string) error {
	var buf bytes.Buffer

	err := encode(&buf)
	if err != nil {
		return fmt.Errorf("encode %s: %w", format, err)
	}

	err = writeFileIfChanged(p.fs, path, buf.Bytes(), filePerm)
	if err != nil {
		return fmt.Errorf("write %s: %w", format, err)
	}

	return nil
}

func (p *pipeline) findDirectory(paths ...string) string {
	for _, candidate := range paths {
		candidate = os.ExpandEnv(candidate)
		if p.fs.IsDir(candidate) {
			return candidate
		}
	}

	return ""
}

func (p *pipeline) ensureDirectories(sourceDir, binaryDir string) error {
	subdirs := []string{categoryDomainSet, categoryIP, categoryNonIP, categoryDNS}
	for _, baseDir := range []string{sourceDir, binaryDir} {
		for _, sub := range subdirs {
			err := p.fs.MkdirAll(filepath.Join(baseDir, sub), dirPerm)
			if err != nil {
				return fmt.Errorf("create directory %q: %w", filepath.Join(baseDir, sub), err)
			}
		}
	}

	return nil
}

func (p *pipeline) collectFiles(dir string, categories []string) ([]RuleFile, error) {
	files := make([]RuleFile, 0, initialRuleFilesCap)

	for _, category := range categories {
		categoryFiles, err := p.collectCategoryFiles(dir, category)
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

func (p *pipeline) collectCategoryFiles(dir string, category string) ([]RuleFile, error) {
	searchDir := categoryDirectory(dir, category)

	entries, err := p.fs.ReadDir(searchDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []RuleFile{}, nil
		}

		return nil, fmt.Errorf("read category directory %q: %w", searchDir, err)
	}

	files := make([]RuleFile, 0, len(entries))
	for _, entry := range entries {
		file, ok := newRuleFile(searchDir, category, entry)
		if ok {
			files = append(files, file)
		}
	}

	return files, nil
}

func writeFileIfChanged(fsys fileSystem, path string, content []byte, perm os.FileMode) error {
	cleanedPath := filepath.Clean(path)

	current, err := fsys.ReadFile(cleanedPath)
	if err == nil && bytes.Equal(current, content) {
		return nil
	}

	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read current file %q: %w", cleanedPath, err)
	}

	err = fsys.WriteFile(cleanedPath, content, perm)
	if err != nil {
		return fmt.Errorf("write file %q: %w", cleanedPath, err)
	}

	return nil
}

func newRuleFile(searchDir, category string, entry fs.DirEntry) (RuleFile, bool) {
	if entry.IsDir() {
		return RuleFile{}, false
	}

	name := entry.Name()
	if filepath.Ext(name) != ".conf" {
		return RuleFile{}, false
	}

	base := strings.TrimSuffix(name, ".conf")
	if base == "" {
		return RuleFile{}, false
	}

	return RuleFile{
		path:     filepath.Join(searchDir, name),
		category: category,
		name:     base,
	}, true
}

func categoryDirectory(dir string, category string) string {
	if category == categoryDNS {
		return dir
	}

	return filepath.Join(dir, category)
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
	fsAdapter := osFileSystem{}

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

	p := newPipeline(fsAdapter, httpSourceOpener{client: client}, singBoxSerializer{})

	sourceDir := filepath.Join("sing-box", "go", "source")
	binaryDir := filepath.Join("sing-box", "go", "binary")

	return p.run(ctx, sourceDir, binaryDir)
}
