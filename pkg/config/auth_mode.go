package config

import "fmt"

const (
	// AuthModeOAuth validates an incoming credential as an OAuth bearer token
	// against Teamwork's Launchpad identity service. This is the default and the
	// only mode Teamwork's own hosted deployment uses.
	AuthModeOAuth = "oauth"

	// AuthModeAPIKey validates an incoming credential as a Teamwork Projects API
	// key using HTTP basic auth against the customer's own installation.
	//
	// This exists because Launchpad is not universal: an installation that does
	// not use it has no identity to resolve there, so every OAuth-mode request
	// answers 401 no matter how the credential is presented. Teamwork's
	// authorization server also advertises only the authorization_code grant
	// (no refresh_token), so an OAuth deployment re-authorises the user whenever
	// the client discards its token. An API key has neither problem: it does not
	// expire and needs no authorization server.
	AuthModeAPIKey = "apikey"
)

// ValidateAuthMode checks that the configured authentication mode is one this
// server implements, and that the configuration it depends on is present.
//
// It is called once at startup rather than per request because a missing
// SiteURL in apikey mode is a deployment error, not a client error: without it
// every request would resolve credentials against the wrong host and fail
// identically to a bad key, which is a difficult failure to diagnose from the
// client side.
func (r *Resources) ValidateAuthMode() error {
	switch r.Info.AuthMode {
	case AuthModeOAuth:
		return nil

	case AuthModeAPIKey:
		if r.Info.SiteURL == "" {
			return fmt.Errorf("TW_MCP_SITE_URL is required when TW_MCP_AUTH_MODE=%s: "+
				"an API key is resolved against the installation itself, which cannot be discovered "+
				"from the credential (for example https://example.teamwork.com)", AuthModeAPIKey)
		}
		return nil

	default:
		return fmt.Errorf("unknown TW_MCP_AUTH_MODE %q: must be %q or %q",
			r.Info.AuthMode, AuthModeOAuth, AuthModeAPIKey)
	}
}
