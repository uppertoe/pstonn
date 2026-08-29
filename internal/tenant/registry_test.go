package tenant

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/config"
)

func TestEmbeddedRegistryIsValid(t *testing.T) {
	reg, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.ByID("stonnington")
	if !ok || c.Name != "City of Stonnington" || c.Connector != "orikan-ssp" || !c.Enabled {
		t.Fatalf("stonnington entry: %+v", c)
	}
	if c.Policy.HomeState != "VIC" || !c.Policy.IsVisitor("(A) 1st Visitor Permit") || !c.Policy.IsResident("(A) 2nd Resident Permit") {
		t.Fatalf("policy not compiled from the file: %+v", c.Policy)
	}
	if c.Location().String() != "Australia/Melbourne" {
		t.Fatalf("timezone = %s", c.Location())
	}
}

func TestLoadAppliesConfigAndSandbox(t *testing.T) {
	reg, err := Load(config.CouncilConfig{Issuer: "https://x/idm", ClientID: "c2"}, "")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := reg.ByID("stonnington")
	if c.Endpoints.Issuer != "https://x/idm" || c.Endpoints.ClientID != "c2" || c.Endpoints.APIBase == "" {
		t.Fatalf("COUNCIL_* overrides not laid over the entry: %+v", c.Endpoints)
	}
	if reg.Default == nil || reg.Default.ID != "stonnington" {
		t.Fatalf("default = %+v", reg.Default)
	}
	sb, err := Load(config.CouncilConfig{Sandbox: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sb.All()) != 1 || sb.Default.Connector != "fake" {
		t.Fatalf("sandbox registry = %+v", sb.All())
	}
}

func TestLoadFromFileAndValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good.json", `{"tenants":[
	  {"id":"stonnington","name":"City of Stonnington","short":"Stonnington","connector":"orikan-ssp",
	   "endpoints":{"issuer":"https://a/idm","api_base":"https://a/ssp-svc","client_id":"x","redirect_uri":"https://a/ssp/callback","scopes":["openid"]},
	   "timezone":"Australia/Melbourne","policy":{"visitor_word":"visitor"},"enabled":false},
	  {"id":"othertown","name":"Othertown Council","short":"Othertown","connector":"fake",
	   "timezone":"Australia/Perth","policy":{"visitor_word":"guest","home_state":"WA"},"enabled":true}
	]}`)
	reg, err := Load(config.CouncilConfig{}, good)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Default.ID != "othertown" || len(reg.Enabled()) != 1 {
		t.Fatalf("default should be the only enabled council: %+v", reg.Default)
	}
	if o, _ := reg.ByID("othertown"); !o.Policy.IsVisitor("Guest Parking Entitlement") || o.Policy.IsVisitor("Visitor Permit") {
		t.Fatal("per-council vocabulary not applied")
	}
	for name, body := range map[string]string{
		"empty":         `{"tenants":[]}`,
		"bad id":        `{"tenants":[{"id":"Bad Town","name":"n","short":"s","connector":"fake","timezone":"UTC","policy":{"visitor_word":"v"},"enabled":true}]}`,
		"no endpoints":  `{"tenants":[{"id":"a","name":"n","short":"s","connector":"orikan-ssp","timezone":"UTC","policy":{"visitor_word":"v"},"enabled":true}]}`,
		"bad connector": `{"tenants":[{"id":"a","name":"n","short":"s","connector":"nope","timezone":"UTC","policy":{"visitor_word":"v"},"enabled":true}]}`,
		"bad timezone":  `{"tenants":[{"id":"a","name":"n","short":"s","connector":"fake","timezone":"Mars/Olympus","policy":{"visitor_word":"v"},"enabled":true}]}`,
		"no visitor":    `{"tenants":[{"id":"a","name":"n","short":"s","connector":"fake","timezone":"UTC","policy":{},"enabled":true}]}`,
		"duplicate":     `{"tenants":[{"id":"a","name":"n","short":"s","connector":"fake","timezone":"UTC","policy":{"visitor_word":"v"},"enabled":true},{"id":"a","name":"n","short":"s","connector":"fake","timezone":"UTC","policy":{"visitor_word":"v"},"enabled":true}]}`,
		"http issuer":   `{"tenants":[{"id":"a","name":"n","short":"s","connector":"orikan-ssp","endpoints":{"issuer":"http://a/idm","api_base":"https://a/ssp-svc","client_id":"x","redirect_uri":"https://a/ssp/callback","scopes":["openid"]},"timezone":"UTC","policy":{"visitor_word":"v"},"enabled":true}]}`,
		"js link":       `{"tenants":[{"id":"a","name":"n","short":"s","connector":"fake","timezone":"UTC","policy":{"visitor_word":"v"},"links":{"portal":"javascript:alert(1)"},"enabled":true}]}`,
		"none enabled":  `{"tenants":[{"id":"a","name":"n","short":"s","connector":"fake","timezone":"UTC","policy":{"visitor_word":"v"},"enabled":false}]}`,
	} {
		if _, err := Load(config.CouncilConfig{}, write(strings.ReplaceAll(name, " ", "_")+".json", body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Load(config.CouncilConfig{}, filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing COUNCILS_PATH must fail loudly, not fall back silently")
	}
}
