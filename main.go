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
	httpTimeout           = 10 * time.Second
	httpPoolTimeout       = 30 * time.Second
	maxConnections        = 100
	maxKeepalive          = 20
	scannerBufSize        = 64 << 10
	scannerMaxSize        = 1 << 20
	filePerm              = 0o644
	dirPerm               = 0o755
	expectContinueDivisor = 2
	maxHTTPHeaderBytes    = 1 << 20
	initialRuleFilesCap   = 64
	initialFrameLinesCap  = 256
	initialLogicalCap     = 4
)

const (
	categoryDomainSet = "domainset"
	categoryIP        = "ip"
	categoryNonIP     = "non_ip"
	categoryDNS       = "dns"
)

var (
	errNoListDir            = errors.New("list directory not found")
	errUnexpectedHTTPStatus = errors.New("unexpected HTTP status")
)

type kind string

const (
	kindDomain         kind = "DOMAIN"
	kindDomainSuffix   kind = "DOMAIN-SUFFIX"
	kindDomainKeyword  kind = "DOMAIN-KEYWORD"
	kindDomainRegex    kind = "DOMAIN-REGEX"
	kindDomainWildcard kind = "DOMAIN-WILDCARD"
	kindIPCIDR         kind = "IP-CIDR"
	kindIPCIDR6        kind = "IP-CIDR6"
	kindSourceIP       kind = "SRC-IP"
	kindDestPort       kind = "DEST-PORT"
	kindInPort         kind = "IN-PORT"
	kindSourcePort     kind = "SRC-PORT"
	kindProcessName    kind = "PROCESS-NAME"
	kindProtocol       kind = "PROTOCOL"
	kindSubnet         kind = "SUBNET"
	kindLogicalAnd     kind = "AND"
	kindLogicalOr      kind = "OR"
	kindLogicalNot     kind = "NOT"
)

func (k kind) isLogical() bool {
	return k == kindLogicalAnd || k == kindLogicalOr || k == kindLogicalNot
}

func parseKind(raw string) (kind, bool) {
	k := kind(strings.ToUpper(strings.TrimSpace(raw)))
	switch k {
	case kindDomain, kindDomainSuffix, kindDomainKeyword, kindDomainRegex, kindDomainWildcard,
		kindIPCIDR, kindIPCIDR6, kindSourceIP, kindDestPort, kindInPort, kindSourcePort,
		kindProcessName, kindProtocol, kindSubnet, kindLogicalAnd, kindLogicalOr, kindLogicalNot:
		return k, true
	}

	return "", false
}

type frame map[kind][]string

type entry struct {
	kind    kind
	address string
}

func (e entry) valid() bool {
	return e.kind != "" && e.address != "" && !isWatermark(e.address)
}

func parseFrame(ctx context.Context, opener source, src string) (frame, error) {
	reader, err := opener.Open(ctx, src)
	if err != nil {
		return nil, fmt.Errorf("open frame source %q: %w", src, err)
	}
	defer func() {
		_ = reader.Close()
	}()

	scannerBuf := make([]byte, scannerBufSize)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(scannerBuf[:0], scannerMaxSize)

	lines := make([]string, 0, initialFrameLinesCap)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("scan frame source %q: %w", src, err)
	}

	return parseLines(lines), nil
}

func parseLines(lines []string) frame {
	fr := make(frame)
	seen := make(map[entry]struct{}, len(lines))

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}

		e := parseLine(line)
		if !e.valid() {
			continue
		}

		if _, dup := seen[e]; dup {
			continue
		}

		seen[e] = struct{}{}
		fr[e.kind] = append(fr[e.kind], e.address)
	}

	return fr
}

func isWatermark(address string) bool {
	return strings.Contains(strings.ToLower(address), "5ukk4w")
}

func parseLine(line string) entry {
	if e, explicit := parseExplicit(line); explicit {
		return e
	}

	return parseImplicit(line)
}

func parseExplicit(line string) (entry, bool) {
	pattern, rest, ok := strings.Cut(line, ",")
	if !ok {
		return entry{}, false
	}

	k, ok := parseKind(pattern)
	if !ok {
		return entry{}, true
	}

	return entry{kind: k, address: joinAddress(rest)}, true
}

func parseImplicit(line string) entry {
	address := strings.Trim(strings.TrimSpace(line), `"'`)
	switch {
	case address == "":
		return entry{}
	case isCIDR(address):
		return entry{kind: kindIPCIDR, address: address}
	case strings.HasPrefix(address, "+"):
		return entry{kind: kindDomainSuffix, address: strings.TrimPrefix(address[1:], ".")}
	default:
		return entry{kind: kindDomain, address: address}
	}
}

func joinAddress(rest string) string {
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

func isCIDR(s string) bool {
	_, err := netip.ParsePrefix(s)
	if err == nil {
		return true
	}

	return M.ParseAddr(s).IsValid()
}

type field uint8

const (
	fDomain field = iota
	fDomainSuffix
	fDomainKeyword
	fDomainRegex
	fIPCIDR
	fSourceIPCIDR
	fNetwork
	fPortRange
	fSourcePortRange
	fProcessName
	fProcessPath
	fProcessPathRegex
	fPackageName
	fPackageNameRegex
)

func portField(r *option.DefaultHeadlessRule) *badoption.Listable[uint16] {
	return &r.Port
}

func sourcePortField(r *option.DefaultHeadlessRule) *badoption.Listable[uint16] {
	return &r.SourcePort
}

type ruleSink func(*option.DefaultHeadlessRule, []string)

type compiler struct {
	sinks          map[kind]ruleSink
	stringFields   []field
	accessors      []func(*option.DefaultHeadlessRule) *badoption.Listable[string]
	processTargets [][]field
}

func singCompiler() *compiler {
	c := &compiler{
		accessors: []func(*option.DefaultHeadlessRule) *badoption.Listable[string]{
			fDomain: func(r *option.DefaultHeadlessRule) *badoption.Listable[string] {
				return &r.Domain
			},
			fDomainSuffix: func(r *option.DefaultHeadlessRule) *badoption.Listable[string] {
				return &r.DomainSuffix
			},
			fDomainKeyword: func(r *option.DefaultHeadlessRule) *badoption.Listable[string] {
				return &r.DomainKeyword
			},
			fDomainRegex: func(r *option.DefaultHeadlessRule) *badoption.Listable[string] {
				return &r.DomainRegex
			},
			fIPCIDR: func(r *option.DefaultHeadlessRule) *badoption.Listable[string] {
				return &r.IPCIDR
			},
			fSourceIPCIDR: func(r *option.DefaultHeadlessRule) *badoption.Listable[string] {
				return &r.SourceIPCIDR
			},
			fNetwork: func(r *option.DefaultHeadlessRule) *badoption.Listable[string] {
				return &r.Network
			},
			fPortRange: func(r *option.DefaultHeadlessRule) *badoption.Listable[string] {
				return &r.PortRange
			},
			fSourcePortRange: func(r *option.DefaultHeadlessRule) *badoption.Listable[string] {
				return &r.SourcePortRange
			},
			fProcessName: func(r *option.DefaultHeadlessRule) *badoption.Listable[string] {
				return &r.ProcessName
			},
			fProcessPath: func(r *option.DefaultHeadlessRule) *badoption.Listable[string] {
				return &r.ProcessPath
			},
			fProcessPathRegex: func(r *option.DefaultHeadlessRule) *badoption.Listable[string] {
				return &r.ProcessPathRegex
			},
			fPackageName: func(r *option.DefaultHeadlessRule) *badoption.Listable[string] {
				return &r.PackageName
			},
			fPackageNameRegex: func(r *option.DefaultHeadlessRule) *badoption.Listable[string] {
				return &r.PackageNameRegex
			},
		},
	}
	c.stringFields = []field{
		fDomain, fDomainSuffix, fDomainKeyword, fDomainRegex, fIPCIDR, fSourceIPCIDR,
		fPortRange, fSourcePortRange, fProcessName, fProcessPath, fProcessPathRegex,
		fPackageName, fPackageNameRegex,
	}

	c.processTargets = [][]field{
		classProcessName:      {fProcessName, fPackageName},
		classProcessPath:      {fProcessPath, fPackageName},
		classProcessPathRegex: {fProcessPathRegex, fPackageNameRegex},
	}
	c.sinks = map[kind]ruleSink{
		kindDomain:         c.setStr(fDomain),
		kindDomainSuffix:   c.setStr(fDomainSuffix),
		kindDomainKeyword:  c.setStr(fDomainKeyword),
		kindDomainRegex:    c.mapSetStr(fDomainRegex, filterValidRegex),
		kindDomainWildcard: c.mapMergeStr(fDomainRegex, maskWildcards),
		kindIPCIDR:         c.mapMergeStr(fIPCIDR, normalizeCIDRs),
		kindIPCIDR6:        c.mapMergeStr(fIPCIDR, normalizeCIDRs),
		kindSourceIP:       c.mapSetStr(fSourceIPCIDR, normalizeCIDRs),
		kindDestPort:       c.setPorts(portField, fPortRange),
		kindInPort:         c.setPorts(portField, fPortRange),
		kindSourcePort:     c.setPorts(sourcePortField, fSourcePortRange),
		kindProtocol:       c.mapSetStr(fNetwork, normalizeProtocols),
		kindSubnet:         foldNetworkType,
	}

	return c
}

func (c *compiler) setStr(f field) ruleSink {
	return func(r *option.DefaultHeadlessRule, raw []string) {
		setList(c.accessors[f](r), raw)
	}
}

func (c *compiler) mapSetStr(f field, m func([]string) []string) ruleSink {
	return func(r *option.DefaultHeadlessRule, raw []string) {
		setList(c.accessors[f](r), m(raw))
	}
}

func (c *compiler) mapMergeStr(f field, m func([]string) []string) ruleSink {
	return func(r *option.DefaultHeadlessRule, raw []string) {
		mergeList(c.accessors[f](r), m(raw))
	}
}

func (c *compiler) setPorts(
	port func(*option.DefaultHeadlessRule) *badoption.Listable[uint16],
	rng field,
) ruleSink {
	return func(r *option.DefaultHeadlessRule, raw []string) {
		ports, ranges := processPorts(raw)
		if len(ports) > 0 {
			setList(port(r), ports)
		}

		setList(c.accessors[rng](r), ranges)
	}
}

func (c *compiler) foldProcess(r *option.DefaultHeadlessRule, raw []string, ax axis) {
	for _, addr := range raw {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}

		class, value := classifyProcess(addr)
		appendValue(c.accessors[c.processTargets[class][ax]](r), value)
	}
}

func (c *compiler) fold(r *option.DefaultHeadlessRule, k kind, raw []string, ax axis) {
	if k == kindProcessName {
		c.foldProcess(r, raw, ax)

		return
	}

	if sink, ok := c.sinks[k]; ok {
		sink(r, raw)
	}
}

func foldNetworkType(r *option.DefaultHeadlessRule, raw []string) {
	for _, addr := range raw {
		iface, ok := parseNetworkType(addr)
		if ok {
			r.NetworkType = append(r.NetworkType, iface)
		}
	}
}

func appendValue(dst *badoption.Listable[string], value string) {
	*dst = append(*dst, value)
}

func setList[T comparable](dst *badoption.Listable[T], values []T) {
	values = common.FilterNotDefault(values)
	if len(values) == 0 {
		*dst = nil

		return
	}

	*dst = badoption.Listable[T](common.Uniq(values))
}

func mergeList[T comparable](dst *badoption.Listable[T], values []T) {
	if len(values) == 0 {
		return
	}

	setList(dst, append(append([]T(nil), (*dst)...), values...))
}

func (c *compiler) finalize(r *option.DefaultHeadlessRule) {
	for _, f := range c.stringFields {
		dst := c.accessors[f](r)
		setList(dst, *dst)
	}

	setList(portField(r), r.Port)
	setList(sourcePortField(r), r.SourcePort)

	if len(r.NetworkType) > 0 {
		r.NetworkType = badoption.Listable[option.InterfaceType](common.Uniq(r.NetworkType))
	}
}

func (c *compiler) compile(fr frame) *option.PlainRuleSet {
	rules := c.compileLogical(fr)
	rules = append(rules, c.compileDefault(fr)...)

	return &option.PlainRuleSet{Rules: rules}
}

func (c *compiler) compileDefault(fr frame) []option.HeadlessRule {
	base := option.DefaultHeadlessRule{}

	for _, k := range defaultKinds(fr) {
		if k == kindProcessName {
			continue
		}

		if sink, ok := c.sinks[k]; ok {
			sink(&base, fr[k])
		}
	}

	c.finalize(&base)

	defaults := make([]option.HeadlessRule, 0, 1+axisCount)
	if base.IsValid() {
		defaults = append(
			defaults,
			option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: base},
		)
	}

	if process := fr[kindProcessName]; len(process) > 0 {
		for ax := range axisCount {
			var rule option.DefaultHeadlessRule
			c.foldProcess(&rule, process, axis(ax))
			c.finalize(&rule)

			if rule.IsValid() {
				defaults = append(
					defaults,
					option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: rule},
				)
			}
		}
	}

	return defaults
}

func defaultKinds(fr frame) []kind {
	kinds := make([]kind, 0, len(fr))
	for k := range fr {
		if !k.isLogical() {
			kinds = append(kinds, k)
		}
	}

	slices.Sort(kinds)

	return kinds
}

type logicalSpec struct {
	kind   kind
	mode   string
	invert bool
}

func (c *compiler) compileLogical(fr frame) []option.HeadlessRule {
	specs := []logicalSpec{
		{kindLogicalAnd, C.LogicalTypeAnd, false},
		{kindLogicalOr, C.LogicalTypeOr, false},
		{kindLogicalNot, C.LogicalTypeAnd, true},
	}

	rules := make([]option.HeadlessRule, 0, len(fr))
	for _, spec := range specs {
		for _, group := range fr[spec.kind] {
			for _, sub := range c.logicalVariants(group) {
				rules = append(rules, logicalRule(sub, spec.mode, spec.invert))
			}
		}
	}

	return rules
}

func (c *compiler) logicalVariants(address string) [][]option.HeadlessRule {
	inner, ok := logicalBody(address)
	if !ok {
		return nil
	}

	parts := splitLogical(inner)

	entries := make([]entry, 0, len(parts))
	axes := 1

	for _, part := range parts {
		e := parseLine(part)

		entries = append(entries, e)
		if e.kind == kindProcessName {
			axes = axisCount
		}
	}

	variants := make([][]option.HeadlessRule, axes)
	for _, e := range entries {
		for ax := range axes {
			rule := c.compileLogicalPart(e, axis(ax))
			if rule != nil {
				variants[ax] = append(variants[ax], *rule)
			}
		}
	}

	out := variants[:0]
	for _, v := range variants {
		if len(v) > 0 {
			out = append(out, v)
		}
	}

	return out
}

func (c *compiler) compileLogicalPart(e entry, ax axis) *option.HeadlessRule {
	if !e.valid() || e.kind.isLogical() {
		return nil
	}

	var rule option.DefaultHeadlessRule
	c.fold(&rule, e.kind, []string{e.address}, ax)
	c.finalize(&rule)

	if !rule.IsValid() {
		return nil
	}

	return &option.HeadlessRule{
		Type:           C.RuleTypeDefault,
		DefaultOptions: rule,
	}
}

func logicalRule(sub []option.HeadlessRule, mode string, invert bool) option.HeadlessRule {
	return option.HeadlessRule{
		Type: C.RuleTypeLogical,
		LogicalOptions: option.LogicalHeadlessRule{
			Mode:   mode,
			Rules:  sub,
			Invert: invert,
		},
	}
}

func logicalBody(address string) (string, bool) {
	if !strings.HasPrefix(address, "((") || !strings.HasSuffix(address, "))") {
		return "", false
	}

	inner := strings.TrimSpace(address[1 : len(address)-1])

	return inner, inner != ""
}

func splitLogical(inner string) []string {
	inner = strings.TrimSpace(inner)
	if inner == "" {
		return nil
	}

	parts := make([]string, 0, initialLogicalCap)
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
				if part := unwrapParens(strings.TrimSpace(inner[start:i])); part != "" {
					parts = append(parts, part)
				}

				start = i + 1
			}
		}
	}

	if tail := unwrapParens(strings.TrimSpace(inner[start:])); tail != "" {
		parts = append(parts, tail)
	}

	return parts
}

func unwrapParens(value string) string {
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

func collectValues(raw []string, normalize func(string) (string, bool)) []string {
	values := make([]string, 0, len(raw))
	for _, v := range raw {
		if n, ok := normalize(v); ok {
			values = append(values, n)
		}
	}

	return common.Uniq(values)
}

func normalizeCIDRs(raw []string) []string {
	return collectValues(raw, func(v string) (string, bool) {
		n := normalizeCIDR(strings.TrimSuffix(strings.TrimSpace(v), ",no-resolve"))

		return n, n != ""
	})
}

func normalizeCIDR(entry string) string {
	entry = strings.TrimSpace(entry)

	prefix, err := netip.ParsePrefix(entry)
	if err == nil {
		return prefix.String()
	}

	if addr := M.ParseAddr(entry); addr.IsValid() {
		if addr.Is4() {
			return addr.String() + "/32"
		}

		return addr.String() + "/128"
	}

	return ""
}

func filterValidRegex(raw []string) []string {
	return collectValues(raw, func(v string) (string, bool) {
		v = strings.TrimSpace(v)

		return v, validateRegex(v)
	})
}

func maskWildcards(raw []string) []string {
	return collectValues(raw, func(v string) (string, bool) {
		v = strings.TrimSpace(v)
		if !isWildcardLike(v) {
			return "", false
		}

		masked := wildcardPatternToRegex(v)

		return masked, validateRegex(masked)
	})
}

func normalizeProtocols(raw []string) []string {
	return collectValues(raw, func(v string) (string, bool) {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v != "TCP" && v != "UDP" {
			return "", false
		}

		return strings.ToLower(v), true
	})
}

func validateRegex(pattern string) bool {
	if pattern == "" {
		return false
	}

	_, err := regexp.Compile(pattern)

	return err == nil
}

func isRegexLike(v string) bool {
	if !strings.ContainsAny(v, `\+*?()|[]{}^$`) {
		return false
	}

	return validateRegex(v)
}

func isWildcardLike(v string) bool {
	v = strings.TrimSpace(v)

	return v != "" && strings.ContainsAny(v, "*?")
}

func isPathLike(v string) bool {
	if v == "" {
		return false
	}

	if filepath.IsAbs(v) || filepath.VolumeName(v) != "" {
		return true
	}

	if strings.ContainsAny(v, `/\`) {
		return true
	}

	cleaned := path.Clean(v)

	return cleaned != "." && strings.Contains(cleaned, "/")
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

type processClass uint8

const (
	classProcessName processClass = iota
	classProcessPath
	classProcessPathRegex
)

type axis uint8

const (
	axisProcess axis = iota
	axisPackage
)

const axisCount = int(axisPackage) + 1

func classifyProcess(addr string) (processClass, string) {
	if masked, ok := processPattern(addr); ok {
		return classProcessPathRegex, masked
	}

	if isPathLike(addr) {
		return classProcessPath, addr
	}

	return classProcessName, addr
}

func processPattern(addr string) (string, bool) {
	if isWildcardLike(addr) {
		masked := maskPathRegex(addr)

		return masked, validateRegex(masked)
	}

	if isRegexLike(addr) {
		return addr, true
	}

	return "", false
}

func processPorts(raw []string) ([]uint16, []string) {
	ports := make([]uint16, 0, len(raw))
	ranges := make([]string, 0, len(raw))

	for _, v := range raw {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		if rng, ok := parsePortRange(v); ok {
			ranges = append(ranges, rng)

			continue
		}

		port, err := parsePort(v)
		if err == nil {
			ports = append(ports, port)
		}
	}

	return common.Uniq(ports), common.Uniq(common.FilterNotDefault(ranges))
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

type format struct {
	path   string
	ext    string
	encode func(io.Writer) error
}

type pipeline struct {
	store      store
	source     source
	serializer serializer
	compiler   *compiler
}

func (p *pipeline) run(ctx context.Context, sourceDir, binaryDir string) error {
	listDir := p.findDir("List", "../List")
	if listDir == "" {
		return errNoListDir
	}

	err := p.ensureDirs(sourceDir, binaryDir)
	if err != nil {
		return err
	}

	files, err := p.collect(listDir, []string{categoryDomainSet, categoryIP, categoryNonIP})
	if err != nil {
		return fmt.Errorf("collect files: %w", err)
	}

	dnsDir := p.findDir(
		"Modules/Rules/sukka_local_dns_mapping",
		"../Modules/Rules/sukka_local_dns_mapping",
	)
	if dnsDir != "" {
		dnsFiles, err := p.collect(dnsDir, []string{categoryDNS})
		if err == nil {
			files = append(files, dnsFiles...)
		}
	}

	worker, workerCtx := batch.New(ctx, batch.WithConcurrencyNum[struct{}](maxConnections))
	for _, file := range files {
		worker.Go(file.path, func() (struct{}, error) {
			return struct{}{}, p.process(workerCtx, file, sourceDir, binaryDir)
		})
	}

	waitErr := worker.Wait()
	if waitErr != nil {
		return fmt.Errorf("wait for workers: %w", waitErr)
	}

	return nil
}

func (p *pipeline) process(ctx context.Context, file ruleFile, sourceDir, binaryDir string) error {
	fr, err := parseFrame(ctx, p.source, "file://"+file.path)
	if err != nil {
		return err
	}

	if len(fr) == 0 {
		return nil
	}

	return p.emit(ctx, fr, file.name, file.category, sourceDir, binaryDir)
}

func (p *pipeline) emit(
	ctx context.Context,
	fr frame,
	name, category, sourceDir, binaryDir string,
) error {
	ruleSet := p.compiler.compile(fr)

	err := p.serializer.Validate(ctx, name, ruleSet)
	if err != nil {
		return fmt.Errorf("validate rule-set: %w", err)
	}

	base := strings.ReplaceAll(name, "_", "-") + "." + category

	formats := []format{
		{
			filepath.Join(sourceDir, category, base+".json"), "json",
			func(w io.Writer) error {
				return p.serializer.EncodeJSON(w, ruleSet)
			},
		},
		{
			filepath.Join(binaryDir, category, base+".srs"), "srs",
			func(w io.Writer) error {
				return p.serializer.EncodeSRS(w, ruleSet)
			},
		},
	}
	for _, f := range formats {
		err := p.writeSerialized(f.path, f.encode, f.ext)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *pipeline) writeSerialized(path string, encode func(io.Writer) error, format string) error {
	var buf bytes.Buffer

	err := encode(&buf)
	if err != nil {
		return fmt.Errorf("encode %s: %w", format, err)
	}

	err = writeIfChanged(p.store, path, buf.Bytes())
	if err != nil {
		return fmt.Errorf("write %s: %w", format, err)
	}

	return nil
}

func writeIfChanged(s store, path string, content []byte) error {
	path = filepath.Clean(path)

	current, err := s.ReadFile(path)
	if err == nil && bytes.Equal(current, content) {
		return nil
	}

	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read current file %q: %w", path, err)
	}

	err = s.WriteFile(path, content, filePerm)
	if err != nil {
		return fmt.Errorf("write file %q: %w", path, err)
	}

	return nil
}

func (p *pipeline) collect(dir string, categories []string) ([]ruleFile, error) {
	files := make([]ruleFile, 0, initialRuleFilesCap)

	for _, category := range categories {
		categoryFiles, err := p.collectCategory(dir, category)
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

func (p *pipeline) collectCategory(dir, category string) ([]ruleFile, error) {
	searchDir := categoryDir(dir, category)

	entries, err := p.store.ReadDir(searchDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
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

func (p *pipeline) findDir(paths ...string) string {
	for _, candidate := range paths {
		if candidate = os.ExpandEnv(candidate); p.store.IsDir(candidate) {
			return candidate
		}
	}

	return ""
}

func (p *pipeline) ensureDirs(sourceDir, binaryDir string) error {
	categories := []string{categoryDomainSet, categoryIP, categoryNonIP, categoryDNS}
	for _, base := range []string{sourceDir, binaryDir} {
		for _, category := range categories {
			err := p.store.MkdirAll(filepath.Join(base, category), dirPerm)
			if err != nil {
				return fmt.Errorf("create directory %q: %w", filepath.Join(base, category), err)
			}
		}
	}

	return nil
}

type ruleFile struct {
	path     string
	category string
	name     string
}

func categoryDir(dir, category string) string {
	if category == categoryDNS {
		return dir
	}

	return filepath.Join(dir, category)
}

func newRuleFile(dir, category string, entry fs.DirEntry) (ruleFile, bool) {
	if entry.IsDir() {
		return ruleFile{}, false
	}

	base := strings.TrimSuffix(entry.Name(), ".conf")
	if base == entry.Name() || base == "" {
		return ruleFile{}, false
	}

	return ruleFile{
		path:     filepath.Join(dir, entry.Name()),
		category: category,
		name:     base,
	}, true
}

type source interface {
	Open(ctx context.Context, src string) (io.ReadCloser, error)
}

type httpSource struct {
	client *http.Client
}

func (s httpSource) Open(ctx context.Context, src string) (io.ReadCloser, error) {
	if after, ok := strings.CutPrefix(src, "file://"); ok {
		reader, err := os.Open(filepath.Clean(after))
		if err != nil {
			return nil, fmt.Errorf("open source file %q: %w", after, err)
		}

		return reader, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %q: %w", src, err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch source %q: %w", src, err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()

		return nil, fmt.Errorf("%w: %d from %q", errUnexpectedHTTPStatus, resp.StatusCode, src)
	}

	return resp.Body, nil
}

type store interface {
	ReadDir(name string) ([]fs.DirEntry, error)
	MkdirAll(path string, perm fs.FileMode) error
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte, perm fs.FileMode) error
	IsDir(path string) bool
}

type osStore struct{}

func (osStore) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := os.ReadDir(name)
	if err != nil {
		return nil, fmt.Errorf("read dir %q: %w", name, err)
	}

	return entries, nil
}

func (osStore) MkdirAll(path string, perm fs.FileMode) error {
	err := os.MkdirAll(path, perm)
	if err != nil {
		return fmt.Errorf("mkdir all %q: %w", path, err)
	}

	return nil
}

func (osStore) ReadFile(name string) ([]byte, error) {
	content, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", name, err)
	}

	return content, nil
}

func (osStore) WriteFile(name string, data []byte, perm fs.FileMode) error {
	err := os.WriteFile(name, data, perm)
	if err != nil {
		return fmt.Errorf("write file %q: %w", name, err)
	}

	return nil
}

func (osStore) IsDir(path string) bool {
	info, err := os.Stat(path)

	return err == nil && info.IsDir()
}

type serializer interface {
	EncodeJSON(w io.Writer, ruleSet *option.PlainRuleSet) error
	EncodeSRS(w io.Writer, ruleSet *option.PlainRuleSet) error
	Validate(ctx context.Context, name string, ruleSet *option.PlainRuleSet) error
}

type singBoxSerializer struct{}

func (singBoxSerializer) EncodeJSON(w io.Writer, ruleSet *option.PlainRuleSet) error {
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

func (singBoxSerializer) EncodeSRS(w io.Writer, ruleSet *option.PlainRuleSet) error {
	err := srs.Write(w, *ruleSet, C.RuleSetVersionCurrent)
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
	for i, rule := range ruleSet.Rules {
		_, err := R.NewHeadlessRule(ctx, rule)
		if err != nil {
			return fmt.Errorf("validate rule set %q rule #%d: %w", name, i, err)
		}
	}

	return nil
}

type resettableTransport struct{ *http.Transport }

func (t *resettableTransport) Reset() {
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
	startContext := adapter.NewHTTPStartContext()
	defer startContext.Close()

	transport := &resettableTransport{&http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
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

	client := &http.Client{Transport: transport, Timeout: httpTimeout}

	p := &pipeline{
		store:      osStore{},
		source:     httpSource{client: client},
		serializer: singBoxSerializer{},
		compiler:   singCompiler(),
	}

	return p.run(ctx, "sing-box/go/source", "sing-box/go/binary")
}
