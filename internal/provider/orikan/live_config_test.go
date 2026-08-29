package orikan

// liveConfig is the City of Stonnington tenant, for the env-gated live tools.
var liveConfig = Config{
	Issuer:      "https://parkingpermits.stonnington.vic.gov.au/idm",
	ClientID:    "ePermits.ssp.web",
	RedirectURI: "https://parkingpermits.stonnington.vic.gov.au/ssp/callback",
	Scopes:      []string{"openid", "profile", "ePermits.ssp.api.all"},
	APIBase:     "https://parkingpermits.stonnington.vic.gov.au/ssp-svc",
}
