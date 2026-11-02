package warrant

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The batch is signed from persisted hourly records; a regenerated record
// that differs is refused (lease evidence 5a.2, BG-7).
func TestBatchFromPersistedRecords(t *testing.T) {
	dir := t.TempDir()
	recs := []UsageRecord{{FirstIndex: 3, LastIndex: 3, Units: 3600, Creditable: 3600}, {FirstIndex: 4, LastIndex: 4, Units: 60, Creditable: 3600}}
	for _, r := range recs {
		b, _ := json.Marshal(r)
		os.WriteFile(filepath.Join(dir, "usage-"+itoa(r.FirstIndex)+".json"), b, 0o644)
	}
	got, err := LoadPersisted(dir, 3, 4)
	if err != nil || len(got) != 2 || got[1].Units != 60 {
		t.Fatalf("load: %v %+v", err, got)
	}
	cmd := "sh -c true"
	if _, err := SignBatchExternal(dir, cmd+" {key} {in} {out}", "k", recs); err != nil {
		t.Fatalf("matching records refused: %v", err)
	}
	changed := []UsageRecord{recs[0], {FirstIndex: 4, LastIndex: 4, Units: 3600, Creditable: 3600}}
	if _, err := SignBatchExternal(dir, cmd+" {key} {in} {out}", "k", changed); err == nil {
		t.Fatal("a regenerated record that differs from the persisted one was signed")
	}
	if _, err := LoadPersisted(dir, 3, 5); err == nil {
		t.Fatal("a missing hour was accepted")
	}
}

func itoa(k uint32) string { return string(rune('0' + k)) }
