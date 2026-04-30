package main

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

func TestValidateRuleSet(t *testing.T) {
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

		err := validateRuleSet(context.Background(), "ok", rs)
		if err != nil {
			t.Fatalf("validateRuleSet: %v", err)
		}
	})

	t.Run("invalid_regex", func(t *testing.T) {
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

		err := validateRuleSet(context.Background(), "invalid_regex", rs)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}

func TestBuildRuleSet(t *testing.T) {
	t.Parallel()

	frame := &ruleFrame{groups: collectFrameGroups(representativeRuleLines())}
	if len(frame.groups) == 0 {
		t.Fatal("expected non-empty frame groups")
	}

	rs := (builder{resolver: nil}).buildRuleSet(context.Background(), frame)

	err := validateRuleSet(context.Background(), "representative", rs)
	if err != nil {
		t.Fatalf("validateRuleSet: %v", err)
	}

	defaultRule := requireDefaultRule(t, rs)
	requireLogicalRule(t, rs)
	assertDefaultRuleCoverage(t, defaultRule)
}

func TestParseRuleLine(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		in      string
		pattern string
		address string
	}{
		{name: "explicit", in: "DOMAIN, example.com", pattern: "DOMAIN", address: "example.com"},
		{
			name:    "explicit_suffix",
			in:      "IP-CIDR,1.2.3.4/32,no-resolve",
			pattern: "IP-CIDR",
			address: "1.2.3.4/32,no-resolve",
		},
		{name: "bare_domain", in: "example.com", pattern: "DOMAIN", address: "example.com"},
		{
			name:    "bare_suffix",
			in:      "+.example.com",
			pattern: "DOMAIN-SUFFIX",
			address: "example.com",
		},
		{name: "bare_ip", in: "192.0.2.1", pattern: "IP-CIDR", address: "192.0.2.1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := parseRuleLine(tc.in)
			if got.pattern != tc.pattern || got.address != tc.address {
				t.Fatalf(
					"parseRuleLine(%q) = %#v, want pattern=%q address=%q",
					tc.in,
					got,
					tc.pattern,
					tc.address,
				)
			}
		})
	}
}

func representativeRuleLines() []string {
	return []string{
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
}

func requireDefaultRule(t *testing.T, rs *option.PlainRuleSet) option.DefaultHeadlessRule {
	t.Helper()

	for _, currentRule := range rs.Rules {
		if currentRule.Type == C.RuleTypeDefault {
			return currentRule.DefaultOptions
		}
	}

	t.Fatalf("expected default headless rule, got %#v", rs.Rules)

	return option.DefaultHeadlessRule{}
}

func requireLogicalRule(t *testing.T, rs *option.PlainRuleSet) {
	t.Helper()

	for _, currentRule := range rs.Rules {
		if currentRule.Type == C.RuleTypeLogical {
			return
		}
	}

	t.Fatalf("expected logical rules (AND/OR/NOT) to be present, got %#v", rs.Rules)
}

func assertDefaultRuleCoverage(t *testing.T, got option.DefaultHeadlessRule) {
	t.Helper()

	requireNonEmptyStrings(t, "DOMAIN", got.Domain)
	requireNonEmptyStrings(t, "DOMAIN-SUFFIX", got.DomainSuffix)
	requireNonEmptyStrings(t, "DOMAIN-KEYWORD", got.DomainKeyword)
	requireNonEmptyStrings(t, "DOMAIN-REGEX/DOMAIN-WILDCARD", got.DomainRegex)
	requireNonEmptyStrings(t, "IP-CIDR/IP-CIDR6", got.IPCIDR)
	requireNonEmptyStrings(t, "SRC-IP", got.SourceIPCIDR)
	requireAnyPortCoverage(t, got)
	requireAnySourcePortCoverage(t, got)
	requireAnyProcessCoverage(t, got)
	requireNetworkTypeCoverage(t, got)
	requireNonEmptyStrings(t, "PROTOCOL", got.Network)
}

func requireNonEmptyStrings[S ~[]string](t *testing.T, label string, values S) {
	t.Helper()

	if len(values) == 0 {
		t.Fatalf("expected %s coverage, got %#v", label, values)
	}
}

func requireAnyPortCoverage(t *testing.T, got option.DefaultHeadlessRule) {
	t.Helper()

	if len(got.Port) == 0 && len(got.PortRange) == 0 {
		t.Fatalf(
			"expected DEST-PORT/IN-PORT coverage, got port=%#v port_range=%#v",
			got.Port,
			got.PortRange,
		)
	}
}

func requireAnySourcePortCoverage(t *testing.T, got option.DefaultHeadlessRule) {
	t.Helper()

	if len(got.SourcePort) == 0 && len(got.SourcePortRange) == 0 {
		t.Fatalf(
			"expected SRC-PORT coverage, got source_port=%#v source_port_range=%#v",
			got.SourcePort,
			got.SourcePortRange,
		)
	}
}

func requireAnyProcessCoverage(t *testing.T, got option.DefaultHeadlessRule) {
	t.Helper()

	if len(got.ProcessName)+len(got.ProcessPath)+len(got.ProcessPathRegex) == 0 {
		t.Fatalf("expected PROCESS-NAME coverage, got %#v", got)
	}
}

func requireNetworkTypeCoverage(t *testing.T, got option.DefaultHeadlessRule) {
	t.Helper()

	if len(got.NetworkType) == 0 {
		t.Fatalf("expected SUBNET coverage, got %#v", got.NetworkType)
	}
}

func TestSplitLogicalParts(t *testing.T) {
	t.Parallel()

	inner := "(DOMAIN,example.org),(IP-CIDR,198.51.100.0/24)"

	parts := splitLogicalParts(inner)
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %#v", parts)
	}

	if parts[0] != "DOMAIN,example.org" {
		t.Fatalf("unexpected parts[0]=%q", parts[0])
	}

	if parts[1] != "IP-CIDR,198.51.100.0/24" {
		t.Fatalf("unexpected parts[1]=%q", parts[1])
	}
}

func TestProcessPorts(t *testing.T) {
	t.Parallel()

	ports, ranges := processPorts([]string{"443", "80-81", "1000:1002", "0", "abc"})
	if len(ports) != 1 || ports[0] != 443 {
		t.Fatalf("unexpected ports %#v", ports)
	}

	if len(ranges) != 2 {
		t.Fatalf("unexpected ranges %#v", ranges)
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

		_, err = rule.NewHeadlessRule(context.Background(), ruleOptions)
		if err != nil {
			t.Fatalf("rule.NewHeadlessRule upgraded rules[%d]: %v", i, err)
		}
	}
}

func anyRuleMatches(
	t *testing.T,
	ctx context.Context,
	rs *option.PlainRuleSet,
	metadata *adapter.InboundContext,
) bool {
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
