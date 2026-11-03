package transfer

import "testing"

func TestNewSlaveZoneCopiesMasters(t *testing.T) {
	masters := []string{"192.0.2.1:53"}
	sz, err := NewSlaveZone(SlaveZoneConfig{ZoneName: "example.com.", Masters: masters})
	if err != nil {
		t.Fatal(err)
	}

	masters[0] = "198.51.100.1:53"
	if got := sz.Config.Masters[0]; got != "192.0.2.1:53" {
		t.Fatalf("stored master aliases caller slice: got %q", got)
	}
}
