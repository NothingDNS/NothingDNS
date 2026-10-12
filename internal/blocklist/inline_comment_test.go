package blocklist

import (
	"os"
	"path/filepath"
	"testing"
)

// F697: a plain domain-per-line list with an inline "# comment" was parsed as
// a hosts line, so the entry became the "#" token and the real domain was
// never blocked.
func TestLoadFileInlineComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	body := "ads.example.com # tracker\n" +
		"0.0.0.0 hosts.example.com # hosts style\n" +
		"plain.example.com\n" +
		"0.0.0.0 nocomment.example.com\n" +
		"tight.example.com#glued\n" +
		"# whole line comment\n" +
		"0.0.0.0 # nothing here\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	bl := New(Config{Enabled: true, Files: []string{path}})
	if err := bl.Load(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"ads.example.com", "hosts.example.com", "plain.example.com", "nocomment.example.com", "tight.example.com"} {
		if !bl.IsBlocked(d) {
			t.Errorf("%s not blocked", d)
		}
	}
	for _, d := range []string{"#", "tracker", "nothing", "0.0.0.0"} {
		if bl.IsBlocked(d) {
			t.Errorf("junk entry %q blocked", d)
		}
	}
	for _, e := range bl.GetEntries() {
		if e.Domain == "#" || e.Domain == "" || e.Domain[0] == '#' {
			t.Errorf("junk entry %+v", e)
		}
	}
}
