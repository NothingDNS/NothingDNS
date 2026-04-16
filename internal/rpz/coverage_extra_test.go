package rpz

import (
	"testing"
)

// ---------------------------------------------------------------------------
// SetEnabled
// ---------------------------------------------------------------------------

func TestEngine_SetEnabled(t *testing.T) {
	e := NewEngine(Config{})
	e.SetEnabled(false)

	if e.IsEnabled() {
		t.Error("expected IsEnabled=false after SetEnabled(false)")
	}

	e.SetEnabled(true)
	if !e.IsEnabled() {
		t.Error("expected IsEnabled=true after SetEnabled(true)")
	}
}

// ---------------------------------------------------------------------------
// AddQNAMERule / ListQNAMERules / RemoveQNAMERule
// ---------------------------------------------------------------------------

func TestEngine_AddQNAMERule(t *testing.T) {
	e := NewEngine(Config{})
	e.AddQNAMERule("evil.example.com.", ActionNXDOMAIN, "")

	rules := e.ListQNAMERules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Pattern != "evil.example.com." {
		t.Errorf("Pattern = %q", rules[0].Pattern)
	}
	if rules[0].Action != ActionNXDOMAIN {
		t.Errorf("Action = %d, want ActionNXDOMAIN", rules[0].Action)
	}
}

func TestEngine_AddQNAMERule_CNAME(t *testing.T) {
	e := NewEngine(Config{})
	e.AddQNAMERule("blocked.example.com.", ActionCNAME, "safe.example.com.")

	rules := e.ListQNAMERules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Action != ActionCNAME {
		t.Errorf("Action = %d, want ActionCNAME", rules[0].Action)
	}
	if rules[0].OverrideData != "safe.example.com." {
		t.Errorf("OverrideData = %q", rules[0].OverrideData)
	}
}

func TestEngine_AddQNAMERule_CaseInsensitive(t *testing.T) {
	e := NewEngine(Config{})
	e.AddQNAMERule("Evil.Example.COM.", ActionDrop, "")

	// Lookup should work with lowercase
	rules := e.ListQNAMERules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Pattern != "evil.example.com." {
		t.Errorf("Pattern should be lowercased, got %q", rules[0].Pattern)
	}
}

func TestEngine_RemoveQNAMERule(t *testing.T) {
	e := NewEngine(Config{})
	e.AddQNAMERule("evil.example.com.", ActionNXDOMAIN, "")
	e.RemoveQNAMERule("evil.example.com.")

	rules := e.ListQNAMERules()
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after remove, got %d", len(rules))
	}
}

func TestEngine_RemoveQNAMERule_CaseInsensitive(t *testing.T) {
	e := NewEngine(Config{})
	e.AddQNAMERule("evil.example.com.", ActionNXDOMAIN, "")
	e.RemoveQNAMERule("EVIL.EXAMPLE.COM.")

	rules := e.ListQNAMERules()
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after case-insensitive remove, got %d", len(rules))
	}
}

func TestEngine_ListQNAMERules_Empty(t *testing.T) {
	e := NewEngine(Config{})
	rules := e.ListQNAMERules()
	if rules == nil || len(rules) != 0 {
		t.Errorf("expected empty non-nil slice, got %v", rules)
	}
}

func TestEngine_AddMultipleRules(t *testing.T) {
	e := NewEngine(Config{})
	e.AddQNAMERule("a.example.com.", ActionNXDOMAIN, "")
	e.AddQNAMERule("b.example.com.", ActionNODATA, "")
	e.AddQNAMERule("c.example.com.", ActionDrop, "")

	rules := e.ListQNAMERules()
	if len(rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(rules))
	}
}

// ---------------------------------------------------------------------------
// GetPolicies
// ---------------------------------------------------------------------------

func TestEngine_GetPolicies_Empty(t *testing.T) {
	e := NewEngine(Config{})
	policies := e.GetPolicies()
	if len(policies) != 0 {
		t.Errorf("expected empty policies, got %v", policies)
	}
}
