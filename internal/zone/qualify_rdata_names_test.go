package zone

import "testing"

func TestQualifyRDataNames(t *testing.T) {
	for _, tc := range []struct{ rtype, in, want string }{
		{"CNAME", "a.example", "a.example."},
		{"CNAME", "a.example.", "a.example."},
		{"CNAME", "www", "www.example.com."},
		{"CNAME", "@", "example.com."},
		{"mx", "10  mail.example", "10  mail.example."},
		{"SRV", "0 0 443 .", "0 0 443 ."},
		{"RP", "admin.example txt", "admin.example. txt.example.com."},
		{"NAPTR", `1 2 "s" "x y" "!a b!c!" r.example`, `1 2 "s" "x y" "!a b!c!" r.example.`},
		{"IPSECKEY", "10 3 2 gw.example AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==", "10 3 2 gw.example. AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ=="},
		{"IPSECKEY", "10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==", "10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ=="},
		{"TXT", "a.example", "a.example"},
		{"A", "192.0.2.1", "192.0.2.1"},
	} {
		if got := QualifyRDataNames(tc.rtype, tc.in, "Example.COM"); got != tc.want {
			t.Errorf("QualifyRDataNames(%s, %q) = %q, want %q", tc.rtype, tc.in, got, tc.want)
		}
	}
}
