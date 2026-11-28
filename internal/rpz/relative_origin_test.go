package rpz

import "testing"

// RFC 1035 section 5.1 defines a domain name without a trailing dot as
// relative to the current origin, including the name supplied to $ORIGIN.
func TestRPZRelativeOriginDirectiveUsesCurrentOrigin_F898(t *testing.T) {
	e := loadRPZText(t, "$ORIGIN rpz.example.\n"+
		"@ 300 IN SOA localhost. hostmaster.localhost. 1 3600 600 86400 300\n"+
		"$ORIGIN example.net.rpz.example.\n"+
		"control CNAME .\n"+
		"$ORIGIN nested\n"+
		"bad CNAME .\n")

	if r := e.QNAMEPolicy("control.example.net."); r == nil || r.Action != ActionNXDOMAIN {
		t.Fatalf("control absolute $ORIGIN: got %#v, want NXDOMAIN", r)
	}
	t.Log("CONTROL OK: an absolute $ORIGIN below the RPZ apex is applied")

	r := e.QNAMEPolicy("bad.nested.example.net.")
	if r == nil || r.Action != ActionNXDOMAIN {
		t.Log("EXPECTED: relative $ORIGIN nested expands below example.net.rpz.example.")
		t.Logf("ACTUAL: bad.nested.example.net. policy = %#v; bad. policy = %#v", r, e.QNAMEPolicy("bad."))
		t.Fatal("PROBLEM CONFIRMED: relative $ORIGIN replaced rather than extended the current origin")
	}
	t.Log("PROBLEM NOT REPRODUCED: relative $ORIGIN used the current origin")
}

func TestRPZChainedRelativeOriginDirectives_F898(t *testing.T) {
	e := loadRPZText(t, "$ORIGIN rpz.example.\n"+
		"@ IN SOA localhost. hostmaster.localhost. 1 3600 600 86400 300\n"+
		"$ORIGIN example.net\n"+
		"$ORIGIN deep\n"+
		"blocked CNAME .\n")
	if r := e.QNAMEPolicy("blocked.deep.example.net."); r == nil || r.Action != ActionNXDOMAIN {
		t.Fatalf("chained relative $ORIGIN directives: got %#v, want NXDOMAIN", r)
	}
}
