package config

import "testing"

// TestScalarHashIsNotTreatedAsComment pins YAML §7.3.1: a '#' only starts a
// comment at the start of a plain scalar or when preceded by white space.
// A '#' glued to the value is part of the value.
//
// Before the fix, readScalar broke on EVERY '#', so "api_key: abc#def" parsed
// as the value "abc" with the remainder silently discarded as a comment — a
// config value could be truncated with no error reported.
func TestScalarHashIsNotTreatedAsComment(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"hash glued to value is kept", "api_key: abc#def\n", "abc#def"},
		{"hash after space starts a comment", "api_key: abc #def\n", "abc"},
		{"hash at scalar start starts a comment", "api_key: #def\n", ""},
		{"multiple hashes in value", "url: http://x/#a#b\n", "http://x/#a#b"},
		{"value with space then hash", "v: a b#c\n", "a b#c"},
		{"hash after value in a mapping", "a: x#y\nb: 2\n", "x#y"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root, err := NewParser(tc.in).ParseMapping()
			if err != nil {
				t.Fatalf("ParseMapping(%q) error: %v", tc.in, err)
			}
			got, ok := firstScalarValue(root)
			if !ok {
				t.Fatalf("no key/value pair parsed from %q (root=%#v)", tc.in, root)
			}
			if got != tc.want {
				t.Errorf("value = %q, want %q", got, tc.want)
			}
		})
	}
}

// firstScalarValue returns the value node of the first key/value pair.
// Mapping children are stored flat as [key, value, key, value, ...].
func firstScalarValue(root *Node) (string, bool) {
	if root == nil || len(root.Children) < 2 {
		return "", false
	}
	v := root.Children[1]
	if v == nil {
		return "", true
	}
	return v.Value, true
}
