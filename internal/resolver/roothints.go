package resolver

// Root hints: IANA root name servers (IPv4 + IPv6).
// Sourced from https://www.internic.net/domain/named.root
// Last verified 2024-01. These change extremely rarely.

// RootHint represents a root server with its name and addresses.
type RootHint struct {
	Name string   // e.g. "a.root-servers.net."
	IPv4 []string // e.g. "198.41.0.4"
	IPv6 []string // e.g. "2001:503:ba3e::2:30"
}

// RootHints returns the 13 IANA root name servers.
func RootHints() []RootHint {
	return []RootHint{
		{Name: "a.root-servers.net.", IPv4: []string{"198.41.0.4"}, IPv6: []string{"2001:503:ba3e::2:30"}},
		{Name: "b.root-servers.net.", IPv4: []string{"199.9.14.201"}, IPv6: []string{"2001:500:200::b"}},
		{Name: "c.root-servers.net.", IPv4: []string{"192.33.4.12"}, IPv6: []string{"2001:500:2::c"}},
		{Name: "d.root-servers.net.", IPv4: []string{"199.7.91.13"}, IPv6: []string{"2001:500:2d::d"}},
		{Name: "e.root-servers.net.", IPv4: []string{"192.203.230.10"}, IPv6: []string{"2001:500:a8::e"}},
		{Name: "f.root-servers.net.", IPv4: []string{"192.5.5.241"}, IPv6: []string{"2001:500:2f::f"}},
		{Name: "g.root-servers.net.", IPv4: []string{"192.112.36.4"}, IPv6: []string{"2001:500:12::d0d"}},
		{Name: "h.root-servers.net.", IPv4: []string{"198.97.190.53"}, IPv6: []string{"2001:500:1::53"}},
		{Name: "i.root-servers.net.", IPv4: []string{"192.36.148.17"}, IPv6: []string{"2001:7fe::53"}},
		{Name: "j.root-servers.net.", IPv4: []string{"192.58.128.30"}, IPv6: []string{"2001:503:c27::2:30"}},
		{Name: "k.root-servers.net.", IPv4: []string{"193.0.14.129"}, IPv6: []string{"2001:7fd::1"}},
		{Name: "l.root-servers.net.", IPv4: []string{"199.7.83.42"}, IPv6: []string{"2001:500:9f::42"}},
		{Name: "m.root-servers.net.", IPv4: []string{"202.12.27.33"}, IPv6: []string{"2001:dc3::35"}},
	}
}
