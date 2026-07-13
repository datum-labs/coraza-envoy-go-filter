// Copyright © 2025 Datum Technology, Inc.
// SPDX-License-Identifier: Apache-2.0

package filter

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

const denyDirectives = `
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS:foo "@rx malicious" "id:1234,phase:1,deny,status:403,msg:'blocked by test',logdata:'seen %{MATCHED_VAR}'"
`

func matchOnce(t *testing.T, query string) (*types.Interruption, types.Transaction) {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(denyDirectives))
	if err != nil {
		t.Fatalf("build waf: %v", err)
	}
	tx := waf.NewTransaction()
	tx.ProcessURI("/anything?"+query, "GET", "HTTP/1.1")
	it := tx.ProcessRequestHeaders()
	if it == nil {
		t.Fatalf("expected interruption, got none")
	}
	if it.RuleID != 1234 {
		t.Fatalf("expected rule 1234, got %d", it.RuleID)
	}
	return it, tx
}

func TestMatchedRuleEventAttrsEmitsMatchedDetail(t *testing.T) {
	it, tx := matchOnce(t, "foo=maliciouspayload")
	defer tx.Close()

	mr := matchedRuleByID(tx.MatchedRules(), it.RuleID)
	if mr == nil {
		t.Fatalf("matchedRuleByID returned nil")
	}

	got := map[string]string{}
	for _, a := range matchedRuleEventAttrs(mr, true) {
		got[string(a.Key)] = a.Value.AsString()
	}

	if got["coraza.rule.message"] != "blocked by test" {
		t.Errorf("rule.message = %q, want %q", got["coraza.rule.message"], "blocked by test")
	}
	if got["coraza.match.variable"] != "ARGS" {
		t.Errorf("match.variable = %q, want %q", got["coraza.match.variable"], "ARGS")
	}
	if got["coraza.match.key"] != "foo" {
		t.Errorf("match.key = %q, want %q", got["coraza.match.key"], "foo")
	}
	if !strings.Contains(got["coraza.match.value"], "maliciouspayload") {
		t.Errorf("match.value = %q, want it to contain %q", got["coraza.match.value"], "maliciouspayload")
	}
}

func TestMatchedRuleEventAttrsGatesValue(t *testing.T) {
	it, tx := matchOnce(t, "foo=maliciouspayload")
	defer tx.Close()

	mr := matchedRuleByID(tx.MatchedRules(), it.RuleID)
	for _, a := range matchedRuleEventAttrs(mr, false) {
		if string(a.Key) == "coraza.match.value" {
			t.Fatalf("match.value emitted with emitValue=false: %q", a.Value.AsString())
		}
	}
}

func TestMatchedRuleEventAttrsTruncatesValue(t *testing.T) {
	it, tx := matchOnce(t, "foo=malicious"+strings.Repeat("A", maxMatchedValueSize*2))
	defer tx.Close()

	mr := matchedRuleByID(tx.MatchedRules(), it.RuleID)
	for _, a := range matchedRuleEventAttrs(mr, true) {
		if string(a.Key) == "coraza.match.value" && len(a.Value.AsString()) > maxMatchedValueSize {
			t.Fatalf("match.value length %d exceeds cap %d", len(a.Value.AsString()), maxMatchedValueSize)
		}
	}
}

func TestMatchedRuleByIDFallsBackToLast(t *testing.T) {
	_, tx := matchOnce(t, "foo=maliciouspayload")
	defer tx.Close()

	rules := tx.MatchedRules()
	if len(rules) == 0 {
		t.Skip("no matched rules")
	}
	got := matchedRuleByID(rules, 999999)
	if got == nil {
		t.Fatalf("expected fallback to last matched rule, got nil")
	}
}

func TestMatchedRuleEventAttrsNil(t *testing.T) {
	if matchedRuleEventAttrs(nil, true) != nil {
		t.Fatalf("expected nil attrs for nil rule")
	}
}
