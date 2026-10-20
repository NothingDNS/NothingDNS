package rpz

import "testing"

// Re-adding a QNAME rule through AddQNAMERule (POST /api/v1/rpz/rules, which
// answers 201 "Rule added") must replace the earlier rule for that pattern,
// not be silently dropped because the priorities tie.
func TestAddQNAMERuleReplacesSamePatternRule(t *testing.T) {
	e := NewEngine(Config{Enabled: true})

	// Control: a different pattern is unaffected.
	e.AddQNAMERule("other.example.com", ActionDrop, "")

	e.AddQNAMERule("bad.example.com", ActionNXDOMAIN, "")
	e.AddQNAMERule("bad.example.com.", ActionPassThrough, "")

	rule := e.QNAMEPolicy("bad.example.com.")
	if rule == nil {
		t.Fatal("FAIL: no rule for bad.example.com")
	}
	if rule.Action != ActionPassThrough {
		t.Fatalf("FAIL: second AddQNAMERule ignored: action = %v, want PassThrough", rule.Action)
	}
	if got := e.QNAMEPolicy("other.example.com."); got == nil || got.Action != ActionDrop {
		t.Fatalf("control: other.example.com rule = %+v, want Drop", got)
	}
}

// A loaded file rule with a better (numerically lower) priority than the
// dynamic rule's 0 must keep winning.
func TestAddQNAMERuleKeepsHigherPriorityFileRule(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	e.addRule(&Rule{Trigger: TriggerQNAME, Pattern: "bad.example.com", Action: ActionNXDOMAIN, Priority: -1, PolicyName: "file"})
	e.AddQNAMERule("bad.example.com", ActionPassThrough, "")
	if rule := e.QNAMEPolicy("bad.example.com."); rule == nil || rule.Action != ActionNXDOMAIN {
		t.Fatalf("higher-priority rule lost: %+v", rule)
	}
}
