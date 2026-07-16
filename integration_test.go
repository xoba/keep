package keep

// Integration smoke test against the real deployment at the built-in
// endpoint. Skipped unless KEEP_TEST_IDENTITY names an identity directory
// whose key an administrator has registered for a test service. Kept
// deliberately read-mostly: one status report and a secret listing —
// nothing that alters service records.

import (
	"os"
	"testing"
)

func TestIntegration(t *testing.T) {
	dir := os.Getenv("KEEP_TEST_IDENTITY")
	if dir == "" {
		t.Skip("KEEP_TEST_IDENTITY not set; integration smoke test skipped")
	}
	c, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PutStatus(DefaultStatus("healthy")); err != nil {
		t.Fatalf("PutStatus: %v", err)
	}
	infos, err := c.ListSelfSecrets()
	if err != nil {
		t.Fatalf("ListSelfSecrets: %v", err)
	}
	t.Logf("integration ok: %d secrets visible", len(infos))
}
