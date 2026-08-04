package config

import (
	"os"
	"strings"
	"testing"
)

// === Environment variable expansion conformance ===

func TestExpandEnvVars_MultipleVars(t *testing.T) {
	os.Setenv("TEST_A", "alpha")
	os.Setenv("TEST_B", "beta")
	defer os.Unsetenv("TEST_A")
	defer os.Unsetenv("TEST_B")

	input := "prefix_${TEST_A}_${TEST_B}_suffix"
	result := expandEnvVars(input)
	want := "prefix_alpha_beta_suffix"
	if result != want {
		t.Errorf("got %q, want %q", result, want)
	}
}

func TestExpandEnvVars_MixedSyntax(t *testing.T) {
	os.Setenv("TEST_SIMPLE", "simpleval")
	os.Setenv("TEST_BRACE", "braceval")
	defer os.Unsetenv("TEST_SIMPLE")
	defer os.Unsetenv("TEST_BRACE")

	input := "$TEST_SIMPLE ${TEST_BRACE} end"
	result := expandEnvVars(input)
	want := "simpleval braceval end"
	if result != want {
		t.Errorf("got %q, want %q", result, want)
	}
}

func TestExpandEnvVars_EmptyString(t *testing.T) {
	result := expandEnvVars("")
	if result != "" {
		t.Errorf("got %q, want empty", result)
	}
}

func TestExpandEnvVars_NoVars(t *testing.T) {
	result := expandEnvVars("plain text with no vars")
	if result != "plain text with no vars" {
		t.Errorf("got %q, want unchanged", result)
	}
}

func TestExpandEnvVars_DollarAtEnd(t *testing.T) {
	result := expandEnvVars("ends with $")
	if result != "ends with $" {
		t.Errorf("got %q, want unchanged", result)
	}
}

func TestExpandEnvVars_UnclosedBrace(t *testing.T) {
	os.Setenv("TEST_X", "value")
	defer os.Unsetenv("TEST_X")

	input := "${TEST_X"
	result := expandEnvVars(input)
	// Should leave unclosed braces as-is
	if result != input {
		t.Errorf("got %q, want %q (unclosed brace left as-is)", result, input)
	}
}

func TestExpandEnvVars_EmptyVarName(t *testing.T) {
	// ${} has an empty variable name — os.LookupEnv("") returns empty string, so the result is empty
	result := expandEnvVars("${}")
	if result != "" {
		t.Errorf("got %q, want empty", result)
	}
}

func TestExpandEnvVars_MissingVar(t *testing.T) {
	// This should warn but not crash — produces empty string
	os.Unsetenv("TEST_DOES_NOT_EXIST")
	result := expandEnvVars("value: ${TEST_DOES_NOT_EXIST}")
	if result != "value: " {
		t.Errorf("got %q, want 'value: '", result)
	}
}

func TestExpandEnvVars_UnderscoreInName(t *testing.T) {
	os.Setenv("TEST_WITH_UNDERSCORE", "ok")
	defer os.Unsetenv("TEST_WITH_UNDERSCORE")

	result := expandEnvVars("$TEST_WITH_UNDERSCORE")
	if result != "ok" {
		t.Errorf("got %q, want %q", result, "ok")
	}
}

func TestExpandEnvVars_NumbersInName(t *testing.T) {
	os.Setenv("TEST_123", "numeric")
	defer os.Unsetenv("TEST_123")

	result := expandEnvVars("$TEST_123")
	if result != "numeric" {
		t.Errorf("got %q, want %q", result, "numeric")
	}
}

func TestExpandEnvVars_AdjacentText(t *testing.T) {
	os.Setenv("TEST_PREFIX", "hello")
	defer os.Unsetenv("TEST_PREFIX")

	result := expandEnvVars("${TEST_PREFIX}_world")
	want := "hello_world"
	if result != want {
		t.Errorf("got %q, want %q", result, want)
	}
}

func TestExpandEnvVars_ValueWithSpecialChars(t *testing.T) {
	os.Setenv("TEST_SPECIAL", "a=b:c/d")
	defer os.Unsetenv("TEST_SPECIAL")

	result := expandEnvVars("${TEST_SPECIAL}")
	if result != "a=b:c/d" {
		t.Errorf("got %q, want 'a=b:c/d'", result)
	}
}

func TestExpandNodeEnvVars_NilNode(t *testing.T) {
	// Should not panic
	expandNodeEnvVars(nil)
}

func TestExpandNodeEnvVars_ScalarNode(t *testing.T) {
	os.Setenv("TEST_NODE", "expanded")
	defer os.Unsetenv("TEST_NODE")

	node := &Node{Type: NodeScalar, Value: "$TEST_NODE"}
	expandNodeEnvVars(node)
	if node.Value != "expanded" {
		t.Errorf("got %q, want %q", node.Value, "expanded")
	}
}

// === Parser conformance: edge cases ===

func TestParser_EmptyInput(t *testing.T) {
	p := NewParser("")
	node, err := p.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node == nil {
		t.Fatal("expected non-nil node")
	}
	if node.Type != NodeMapping {
		t.Errorf("expected Mapping, got %v", node.Type)
	}
}

func TestParser_OnlyWhitespace(t *testing.T) {
	// Whitespace-only input is treated as empty by the parser
	p := NewParser("   \t\n  \n  ")
	_, err := p.ParseMapping()
	if err == nil {
		t.Error("expected error for whitespace-only input")
	}
}

func TestParser_OnlyComments(t *testing.T) {
	p := NewParser("# just a comment\n# another comment")
	node, err := p.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParser_KeyWithComment(t *testing.T) {
	input := `key: value # inline comment`
	p := NewParser(input)
	node, err := p.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v := node.GetString("key"); v != "value" {
		t.Errorf("got %q, want %q", v, "value")
	}
}

func TestParser_ValueWithLeadingTrailingWhitespace(t *testing.T) {
	input := `key:   spaced   `
	p := NewParser(input)
	node, err := p.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v := node.GetString("key")
	if !strings.Contains(v, "spaced") {
		t.Errorf("expected 'spaced' in value, got %q", v)
	}
}

func TestParser_DeeplyNestedMapping(t *testing.T) {
	input := `a:
  b:
    c:
      d: deep`
	p := NewParser(input)
	node, err := p.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	a := node.Get("a")
	if a == nil {
		t.Fatal("expected 'a' key")
	}
	b := a.Get("b")
	if b == nil {
		t.Fatal("expected 'a.b' key")
	}
	c := b.Get("c")
	if c == nil {
		t.Fatal("expected 'a.b.c' key")
	}
	if v := c.GetString("d"); v != "deep" {
		t.Errorf("got %q, want %q", v, "deep")
	}
}

func TestParser_BlockSequence(t *testing.T) {
	input := `servers:
  - 1.1.1.1
  - 8.8.8.8`
	p := NewParser(input)
	node, err := p.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seq := node.Get("servers")
	if seq == nil {
		t.Fatal("expected 'servers' key")
	}
	if seq.Type != NodeSequence {
		t.Errorf("expected Sequence, got %v", seq.Type)
	}
	if len(seq.Children) != 2 {
		t.Errorf("expected 2 items, got %d", len(seq.Children))
	}
}

func TestParser_MultipleKeys(t *testing.T) {
	input := `key1: val1
key2: val2
key3: val3`
	p := NewParser(input)
	node, err := p.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v := node.GetString("key1"); v != "val1" {
		t.Errorf("key1: got %q, want %q", v, "val1")
	}
	if v := node.GetString("key2"); v != "val2" {
		t.Errorf("key2: got %q, want %q", v, "val2")
	}
	if v := node.GetString("key3"); v != "val3" {
		t.Errorf("key3: got %q, want %q", v, "val3")
	}
}

func TestParser_QuotedKeys(t *testing.T) {
	input := `"quoted key": value`
	p := NewParser(input)
	node, err := p.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v := node.GetString("quoted key"); v != "value" {
		t.Errorf("got %q, want %q", v, "value")
	}
}

func TestParser_TrailingNewline(t *testing.T) {
	input := "key: value\n"
	p := NewParser(input)
	node, err := p.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v := node.GetString("key"); v != "value" {
		t.Errorf("got %q, want %q", v, "value")
	}
}

func TestParser_MixedSequenceAndMapping(t *testing.T) {
	input := `upstream:
  - address: 1.1.1.1
    port: 53
  - address: 8.8.8.8
    port: 53`
	p := NewParser(input)
	node, err := p.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seq := node.Get("upstream")
	if seq == nil || seq.Type != NodeSequence {
		t.Fatal("expected upstream sequence")
	}
	if len(seq.Children) != 2 {
		t.Fatalf("expected 2 upstream entries, got %d", len(seq.Children))
	}
	first := seq.Children[0]
	if first.Type != NodeMapping {
		t.Fatalf("expected Mapping in sequence, got %v", first.Type)
	}
	if v := first.GetString("address"); v != "1.1.1.1" {
		t.Errorf("got %q, want %q", v, "1.1.1.1")
	}
}

func TestDeploymentConfigsPreserveOperationalInvariants(t *testing.T) {
	t.Setenv("NOTHINGDNS_AUTH_TOKEN", "Staging1!Token2@Secure3#Value4$")
	t.Setenv("NOTHINGDNS_METRICS_AUTH_TOKEN", "Metrics1!Token2@Secure3#Value4$")

	stagingData, err := os.ReadFile("../../deploy/staging.yaml")
	if err != nil {
		t.Fatalf("read staging config: %v", err)
	}
	staging, err := UnmarshalYAML(string(stagingData))
	if err != nil {
		t.Fatalf("parse staging config: %v", err)
	}
	if staging.Metrics.AuthToken != "Metrics1!Token2@Secure3#Value4$" {
		t.Fatalf("staging metrics auth token was not sourced from the environment")
	}

	productionData, err := os.ReadFile("../../deploy/production.yaml")
	if err != nil {
		t.Fatalf("read production config: %v", err)
	}
	production, err := UnmarshalYAMLWithEnv(string(productionData), false)
	if err != nil {
		t.Fatalf("parse production config: %v", err)
	}
	if effectiveTLSBind(production.Server.TLS.Bind) == effectiveTLSBind(production.Server.XoT.Bind) {
		t.Fatalf("production DoT and XoT listeners collide on %q", effectiveTLSBind(production.Server.TLS.Bind))
	}
}

func TestParser_EmptyValues(t *testing.T) {
	input := `empty_key:
bool_key: true
int_key: 42`
	p := NewParser(input)
	node, err := p.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v := node.GetString("empty_key"); v != "" {
		t.Errorf("empty_key: got %q, want %q", v, "")
	}
	if v := node.GetString("bool_key"); v != "true" {
		t.Errorf("bool_key: got %q, want %q", v, "true")
	}
	if v := node.GetString("int_key"); v != "42" {
		t.Errorf("int_key: got %q, want %q", v, "42")
	}
}
