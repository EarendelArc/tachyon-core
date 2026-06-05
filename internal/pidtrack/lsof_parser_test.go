package pidtrack

import "testing"

func TestParseLsofFieldOutput(t *testing.T) {
	input := "p123\ncsteam_osx\nn127.0.0.1:54321->93.184.216.34:443\np456\ncGame\nn*:27015\n"

	records, err := parseLsofFieldOutput(input)
	if err != nil {
		t.Fatalf("parseLsofFieldOutput() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d, want 2", len(records))
	}
	if records[0].PID != 123 || records[0].Name != "steam_osx" {
		t.Fatalf("records[0] = %+v", records[0])
	}
	if got := records[1].Names[0]; got != "*:27015" {
		t.Fatalf("records[1].Names[0] = %q", got)
	}
}

func TestLsofRecordMatchesTCPFlow(t *testing.T) {
	record := lsofRecord{
		PID:   123,
		Name:  "cs2",
		Names: []string{"127.0.0.1:54321->93.184.216.34:443 (ESTABLISHED)"},
	}

	if !lsofRecordMatchesFlow(record, FlowKey{
		Transport:  TransportTCP,
		LocalIP:    "127.0.0.1",
		LocalPort:  54321,
		RemoteIP:   "93.184.216.34",
		RemotePort: 443,
	}) {
		t.Fatal("expected lsof record to match TCP flow")
	}
}

func TestLsofRecordMatchesUDPWildcard(t *testing.T) {
	record := lsofRecord{
		PID:   456,
		Name:  "Game",
		Names: []string{"*:27015"},
	}

	if !lsofRecordMatchesFlow(record, FlowKey{
		Transport: TransportUDP,
		LocalIP:   "192.168.1.20",
		LocalPort: 27015,
	}) {
		t.Fatal("expected wildcard lsof record to match UDP flow")
	}
}

func TestLsofRecordRejectsDifferentPort(t *testing.T) {
	record := lsofRecord{
		PID:   456,
		Name:  "Game",
		Names: []string{"192.168.1.20:27016"},
	}

	if lsofRecordMatchesFlow(record, FlowKey{
		Transport: TransportUDP,
		LocalIP:   "192.168.1.20",
		LocalPort: 27015,
	}) {
		t.Fatal("expected different local port to be rejected")
	}
}
