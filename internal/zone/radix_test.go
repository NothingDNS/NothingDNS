package zone

import (
	"testing"
)

func TestRadixTree_InsertAndFind(t *testing.T) {
	z1 := &Zone{Origin: "example.com."}
	z2 := &Zone{Origin: "example.org."}
	z3 := &Zone{Origin: "com."}
	z4 := &Zone{Origin: "org."}
	z5 := &Zone{Origin: "."} // root zone

	tree := NewRadixTree()
	tree.Insert("example.com.", z1)
	tree.Insert("example.org.", z2)
	tree.Insert("com.", z3)
	tree.Insert("org.", z4)
	tree.Insert(".", z5)

	tests := []struct {
		name     string
		qname    string
		expected *Zone
	}{
		{"exact www.example.com", "www.example.com.", z1},
		{"exact example.com", "example.com.", z1},
		{"exact example.org", "example.org.", z2},
		{"closest encloser www.example.com", "www.example.com.", z1},
		{"closest encloser mail.example.com", "mail.example.com.", z1},
		{"closest encloser api.example.org", "api.example.org.", z2},
		{"root zone", ".", z5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tree.Find(tt.qname)
			if got != tt.expected {
				if tt.expected == nil {
					t.Errorf("expected nil, got %v", got)
				} else {
					t.Errorf("expected %v, got %v", tt.expected.Origin, got.Origin)
				}
			}
		})
	}
}

func TestRadixTree_BuildAndFind(t *testing.T) {
	zones := map[string]*Zone{
		"example.com.": {Origin: "example.com."},
		"example.org.": {Origin: "example.org."},
		"com.":         {Origin: "com."},
	}

	tree := BuildRadixTree(zones)

	if got := tree.Find("www.example.com."); got == nil || got.Origin != "example.com." {
		t.Errorf("www.example.com.: expected example.com., got %v", got)
	}
	if got := tree.Find("example.com."); got == nil || got.Origin != "example.com." {
		t.Errorf("example.com.: expected example.com., got %v", got)
	}
	if got := tree.Find("foo.bar.example.org."); got == nil || got.Origin != "example.org." {
		t.Errorf("foo.bar.example.org.: expected example.org., got %v", got)
	}
}

func TestSplitDomainReversed(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"simple", "example.com.", []string{"com", "example"}},
		{"subdomain", "www.example.com.", []string{"com", "example", "www"}},
		{"three labels", "mail.google.com.", []string{"com", "google", "mail"}},
		{"single label", "localhost.", []string{"localhost"}},
		{"root", ".", []string{"."}},
		{"empty", "", []string{""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitDomainReversed(tt.input)
			if len(got) != len(tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, got)
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("expected %v, got %v", tt.expected, got)
					return
				}
			}
		})
	}
}

func TestRadixTree_Empty(t *testing.T) {
	tree := NewRadixTree()
	if got := tree.Find("anything.com."); got != nil {
		t.Errorf("expected nil for empty tree, got %v", got)
	}
}

func TestRadixTree_BuildEmptyMap(t *testing.T) {
	tree := BuildRadixTree(nil)
	if tree == nil {
		t.Errorf("BuildRadixTree(nil) should return a valid tree")
	}
	if got := tree.Find("anything.com."); got != nil {
		t.Errorf("expected nil for empty tree, got %v", got)
	}
}
