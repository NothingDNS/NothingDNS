package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
)

// captureWarnings collects everything util.Warnf emits while fn runs.
func captureWarnings(t *testing.T, fn func()) string {
	t.Helper()
	var sb strings.Builder
	prev := util.GetDefaultLogger()
	util.SetDefaultLogger(util.NewLogger(util.WARN, util.TextFormat, &sb))
	defer util.SetDefaultLogger(prev)
	fn()
	return sb.String()
}

func parseConfigNode(t *testing.T, yaml string) *Node {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	node, err := NewParser(string(data)).ParseMapping()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return node
}

// TestWarnUnknownNestedKeys_ServerListen is the regression for the foot-gun
// that motivated the check: the loader's key is `bind`, and a config written
// with `listen` was accepted in silence. `-validate-config` reported the file
// valid and the daemon bound every interface, so an operator who meant to
// expose the resolver to loopback exposed it to the whole network instead.
func TestWarnUnknownNestedKeys_ServerListen(t *testing.T) {
	node := parseConfigNode(t, "server:\n  listen: \"127.0.0.1\"\n  port: 53\n")

	out := captureWarnings(t, func() {
		warnUnknownNestedKeys(node, reflect.TypeOf(Config{}))
	})

	if !strings.Contains(out, `unknown key "listen" in section "server"`) {
		t.Errorf("server.listen was not reported; warnings were:\n%s", out)
	}
	if strings.Contains(out, `"port"`) {
		t.Errorf("the valid key `port` was reported:\n%s", out)
	}
}

func TestWarnUnknownNestedKeys_NestedDepth(t *testing.T) {
	node := parseConfigNode(t, strings.Join([]string{
		"server:",
		"  port: 53",
		"  tls:",
		"    enabled: true",
		"    certfile: /x.pem", // real key is cert_file
		"  http:",
		"    enabled: true",
		"    doh_enable: true", // real key is doh_enabled
		"",
	}, "\n"))

	out := captureWarnings(t, func() {
		warnUnknownNestedKeys(node, reflect.TypeOf(Config{}))
	})

	for _, want := range []string{
		`unknown key "certfile" in section "server.tls"`,
		`unknown key "doh_enable" in section "server.http"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing warning %q; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, `"enabled"`) || strings.Contains(out, `"port"`) {
		t.Errorf("valid keys were reported:\n%s", out)
	}
}

// TestWarnUnknownNestedKeys_TopLevelIsNotReChecked: unmarshalToConfig owns the
// document root, with its own split between typos and stale-but-documented
// sections. Duplicating it here would double every root warning.
func TestWarnUnknownNestedKeys_TopLevelIsNotReChecked(t *testing.T) {
	node := parseConfigNode(t, "not_a_real_section:\n  x: 1\n")

	out := captureWarnings(t, func() {
		warnUnknownNestedKeys(node, reflect.TypeOf(Config{}))
	})

	if out != "" {
		t.Errorf("top-level key was reported by the nested check:\n%s", out)
	}
}

// TestWarnUnknownNestedKeys_ExampleConfigIsClean is the false-positive guard:
// the shipped example must not produce a single warning, or operators learn to
// ignore them. It also pins the example against drifting into documenting keys
// the loader does not read — which is exactly how `upstream.timeout` survived.
func TestWarnUnknownNestedKeys_ExampleConfigIsClean(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Skipf("example config not readable: %v", err)
	}
	node, err := NewParser(string(data)).ParseMapping()
	if err != nil {
		t.Fatalf("parse example config: %v", err)
	}

	out := captureWarnings(t, func() {
		warnUnknownNestedKeys(node, reflect.TypeOf(Config{}))
	})

	if out != "" {
		t.Errorf("config.example.yaml documents keys the loader ignores:\n%s", out)
	}
}

func TestYamlFields_SkipsUntaggedAndIgnored(t *testing.T) {
	type sample struct {
		Kept    string `yaml:"kept"`
		Ignored string `yaml:"-"`
		Untaged string
		Options string `yaml:"opts,omitempty"`
	}
	got := yamlFields(reflect.TypeOf(sample{}))

	if _, ok := got["kept"]; !ok {
		t.Error("tagged field missing")
	}
	if _, ok := got["opts"]; !ok {
		t.Error("tag options were not stripped")
	}
	if len(got) != 2 {
		t.Errorf("yamlFields returned %d entries, want 2: %v", len(got), got)
	}
}
