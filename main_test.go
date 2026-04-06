package main

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	t.Run("ok", func(t *testing.T) {
		t.Parallel()
		rs := &option.PlainRuleSet{
			Rules: []option.HeadlessRule{
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultHeadlessRule{
						Domain: badoption.Listable[string]{"example.com"},
					},
				},
			},
		}
		if err := validateRuleSet(context.Background(), "ok", rs); err != nil {
			t.Fatalf("validateRuleSet: %v", err)
		}
	})

	t.Run("bad_regex", func(t *testing.T) {
		t.Parallel()
		rs := &option.PlainRuleSet{
			Rules: []option.HeadlessRule{
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultHeadlessRule{
						DomainRegex: badoption.Listable[string]{"["},
					},
				},
			},
		}
		if err := validateRuleSet(context.Background(), "bad_regex", rs); err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}

func TestComposeFile(t *testing.T) {
	t.Parallel()

	lines := []string{
		"DOMAIN,example.com",
		"DOMAIN-SUFFIX,+.example.org",
		"DOMAIN-KEYWORD,example",
		"DOMAIN-REGEX,^example\\.com$",
		"DOMAIN-WILDCARD,*.example?.com",
		"IP-CIDR,1.2.3.4/32,no-resolve",
		"IP-CIDR,10.0.0.0/8,no-resolve",
		"IP-CIDR6,2001:db8::/32",
		"SRC-IP,192.0.2.0/24",
		"DEST-PORT,1234",
		"IN-PORT,443",
		"SRC-PORT,12345",
		"PROCESS-NAME,example",
		"PROCESS-NAME,example*",
		"SUBNET,wifi",
		"PROTOCOL,tcp",
		"AND,((DOMAIN,example.org),(IP-CIDR,198.51.100.0/24))",
		"OR,((DOMAIN-SUFFIX,example.net),(DEST-PORT,80))",
		"NOT,((PROCESS-NAME,example),(PROTOCOL,udp))",
	}

	frame := frameFromLines(lines)
	if frame == nil {
		t.Fatal("expected non-nil frame")
	}

	rs, err := composeFile(context.Background(), nil, frame)
	if err != nil {
		t.Fatalf("composeFile: %v", err)
	}
	if err := validateRuleSet(context.Background(), "representative", rs); err != nil {
		t.Fatalf("validateRuleSet: %v", err)
	}

	if len(rs.Rules) == 0 {
		t.Fatalf("expected non-empty rules, got %#v", rs.Rules)
	}
	var (
		defaultFound bool
		logicalFound bool
		got          option.DefaultHeadlessRule
	)
	for _, rule := range rs.Rules {
		switch rule.Type {
		case C.RuleTypeDefault:
			got = rule.DefaultOptions
			defaultFound = true
		case C.RuleTypeLogical:
			logicalFound = true
		}
	}
	if !defaultFound {
		t.Fatalf("expected default headless rule, got %#v", rs.Rules)
	}
	if !logicalFound {
		t.Fatalf("expected logical rules (AND/OR/NOT) to be present, got %#v", rs.Rules)
	}
	if len(got.Domain) == 0 {
		t.Fatalf("expected DOMAIN coverage, got %#v", got.Domain)
	}
	if len(got.DomainSuffix) == 0 {
		t.Fatalf("expected DOMAIN-SUFFIX coverage, got %#v", got.DomainSuffix)
	}
	if len(got.DomainKeyword) == 0 {
		t.Fatalf("expected DOMAIN-KEYWORD coverage, got %#v", got.DomainKeyword)
	}
	if len(got.DomainRegex) == 0 {
		t.Fatalf("expected DOMAIN-REGEX/DOMAIN-WILDCARD coverage, got %#v", got.DomainRegex)
	}
	if len(got.IPCIDR) == 0 {
		t.Fatalf("expected IP-CIDR/IP-CIDR6 coverage, got %#v", got.IPCIDR)
	}
	if len(got.SourceIPCIDR) == 0 {
		t.Fatalf("expected SRC-IP coverage, got %#v", got.SourceIPCIDR)
	}
	if len(got.Port) == 0 && len(got.PortRange) == 0 {
		t.Fatalf("expected DEST-PORT/IN-PORT coverage, got port=%#v port_range=%#v", got.Port, got.PortRange)
	}
	if len(got.SourcePort) == 0 && len(got.SourcePortRange) == 0 {
		t.Fatalf("expected SRC-PORT coverage, got source_port=%#v source_port_range=%#v", got.SourcePort, got.SourcePortRange)
	}
	if len(got.ProcessName)+len(got.ProcessPath)+len(got.ProcessPathRegex) == 0 {
		t.Fatalf("expected PROCESS-NAME coverage, got %#v", got)
	}
	if len(got.NetworkType) == 0 {
		t.Fatalf("expected SUBNET coverage, got %#v", got.NetworkType)
	}
	if len(got.Network) == 0 {
		t.Fatalf("expected PROTOCOL coverage, got %#v", got.Network)
	}
}

func TestRuleMatch(t *testing.T) {
	t.Parallel()

	rs := &option.PlainRuleSet{
		Rules: []option.HeadlessRule{
			{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultHeadlessRule{
					Domain: badoption.Listable[string]{"example.com"},
				},
			},
			{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultHeadlessRule{
					IPCIDR: badoption.Listable[string]{"192.0.2.0/24"},
				},
			},
		},
	}

	t.Run("domain", func(t *testing.T) {
		t.Parallel()

		var metadata adapter.InboundContext
		metadata.Domain = "example.com"
		if !anyRuleMatches(t, context.Background(), rs, &metadata) {
			t.Fatalf("expected match for domain %q", metadata.Domain)
		}
	})

	t.Run("ip", func(t *testing.T) {
		t.Parallel()

		var metadata adapter.InboundContext
		ip := netip.MustParseAddr("192.0.2.123")
		metadata.Destination = M.SocksaddrFrom(ip, 0)
		if !anyRuleMatches(t, context.Background(), rs, &metadata) {
			t.Fatalf("expected match for ip %s", ip)
		}
	})
}

func TestPlainRuleSetCompatRoundTripJSON(t *testing.T) {
	t.Parallel()

	original := option.PlainRuleSetCompat{
		Version: C.RuleSetVersionCurrent,
		Options: option.PlainRuleSet{
			Rules: []option.HeadlessRule{
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultHeadlessRule{
						Domain: badoption.Listable[string]{"example.com"},
					},
				},
				{
					Type: C.RuleTypeLogical,
					LogicalOptions: option.LogicalHeadlessRule{
						Mode: C.LogicalTypeAnd,
						Rules: []option.HeadlessRule{
							{
								Type: C.RuleTypeDefault,
								DefaultOptions: option.DefaultHeadlessRule{
									IPCIDR: badoption.Listable[string]{"192.0.2.0/24"},
								},
							},
						},
					},
				},
			},
		},
	}

	payload, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	decoded, err := json.UnmarshalExtended[option.PlainRuleSetCompat](payload)
	if err != nil {
		t.Fatalf("json.UnmarshalExtended: %v", err)
	}

	upgraded, err := decoded.Upgrade()
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}

	if len(upgraded.Rules) == 0 {
		t.Fatalf("expected non-empty upgraded rules")
	}

	for i, ruleOptions := range upgraded.Rules {
		if !ruleOptions.IsValid() {
			t.Fatalf("upgraded rules[%d] invalid: %#v", i, ruleOptions)
		}
		if _, err := rule.NewHeadlessRule(context.Background(), ruleOptions); err != nil {
			t.Fatalf("rule.NewHeadlessRule upgraded rules[%d]: %v", i, err)
		}
	}
}

func anyRuleMatches(t *testing.T, ctx context.Context, rs *option.PlainRuleSet, metadata *adapter.InboundContext) bool {
	t.Helper()

	for i, ruleOptions := range rs.Rules {
		currentRule, err := rule.NewHeadlessRule(ctx, ruleOptions)
		if err != nil {
			t.Fatalf("rule.NewHeadlessRule rules[%d]: %v", i, err)
		}
		if currentRule.Match(metadata) {
			return true
		}
	}
	return false
}

func frameFromLines(lines []string) *ruleFrame {
	groups := make(map[string][]string, 32)
	seen := make(map[ruleEntry]struct{}, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		entry := parseLine(line)
		if entry.pattern == "" || entry.address == "" {
			continue
		}
		if _, excluded := excludedAddresses[entry.address]; excluded {
			continue
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		groups[entry.pattern] = append(groups[entry.pattern], entry.address)
	}
	if len(groups) == 0 {
		return nil
	}
	return &ruleFrame{groups: groups}
}
