package tenant

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/config"
)

// The registry-level guarantees a new tenant entry gets for free: a misspelt key
// cannot be silently ignored, a scheme the scheduler cannot drive cannot be
// enabled, and the read-only accessors hand out copies.

func TestRegistryRefusesUnknownFields(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := `{"id":"a","name":"n","short":"s","connector":"fake","model":"swap","timezone":"UTC","policy":{"visitor_word":"v"},"enabled":true`
	for name, body := range map[string]string{
		"top-level typo":  `{"tenants":[` + base + `,"enable":false}]}`,
		"retired field":   `{"tenants":[` + base + `,"capacity":5}]}`,
		"policy typo":     `{"tenants":[` + base + `,"policy":{"visitor_word":"v","resident_words":"r"}}]}`,
		"endpoints typo":  `{"tenants":[` + base + `,"endpoints":{"isuer":"https://a/idm"}}]}`,
		"links typo":      `{"tenants":[` + base + `,"links":{"portal_url":"https://a/"}}]}`,
		"stray root key":  `{"tenants":[` + base + `}],"tenant":[]}`,
		"replate enabled": `{"tenants":[{"id":"a","name":"n","short":"s","connector":"fake","model":"replate","timezone":"UTC","policy":{"resident_word":"resident","schedule_resident":true},"enabled":true}]}`,
	} {
		_, err := Load(config.CouncilConfig{}, write(strings.ReplaceAll(name, " ", "_")+".json", body))
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Re-plate is describable while disabled, so the survey's councils can be
	// on file ahead of the restore path.
	body := `{"tenants":[` + base + `},{"id":"b","name":"n","short":"s","connector":"fake","model":"replate","timezone":"UTC","policy":{"resident_word":"resident","schedule_resident":true},"enabled":false}]}`
	if _, err := Load(config.CouncilConfig{}, write("replate_disabled.json", body)); err != nil {
		t.Errorf("disabled replate refused: %v", err)
	}
	// Every endpoint given must be https, whatever the connector: the fake with an
	// http endpoint is a descriptor someone will copy for a real portal.
	body = `{"tenants":[` + base + `,"endpoints":{"issuer":"http://a/idm"}}]}`
	if _, err := Load(config.CouncilConfig{}, write("fake_http.json", body)); err == nil {
		t.Error("http endpoint on a fake tenant accepted")
	}
}

func TestEmbeddedAccessorsHandOutCopies(t *testing.T) {
	a, b := Default(), Default()
	if a == b {
		t.Fatal("Default returned the same pointer twice")
	}
	a.Name = "mutated"
	if Default().Name == "mutated" || Stonnington().Name == "mutated" {
		t.Fatal("a caller's mutation leaked into the shared embedded registry")
	}
	// The compiled policy survives the copy (no per-call regexp rebuild).
	if Default().Policy.residentRe == nil {
		t.Fatal("Default's policy is not compiled")
	}
}

func TestConnectorsListIsStable(t *testing.T) {
	got := strings.Join(Connectors(), ",")
	if got != "fake,orikan-ssp,orikan-ssp-v7" {
		t.Fatalf("Connectors() = %q; adding a connector means adding it here AND in connectors.Build (its tests hold the two together)", got)
	}
}
