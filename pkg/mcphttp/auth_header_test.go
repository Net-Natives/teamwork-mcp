package mcphttp

import (
	"testing"

	"github.com/teamwork/mcp/pkg/config"
)

// TestExtractCredential pins which Authorization header forms each auth mode
// accepts. The API key cases exist because the Messages API sends
// "Bearer <token>" (it adds the scheme to authorization_token itself) while a
// claude.ai connector Request header is sent verbatim — so the same key is
// correct with the prefix in one place and without it in the other.
func TestExtractCredential(t *testing.T) {
	const key = "twp_testkey_eu"

	tests := []struct {
		name     string
		authMode string
		header   string
		want     string
		wantOK   bool
	}{
		// Both modes accept the standard form.
		{
			name:     "oauth accepts Bearer",
			authMode: config.AuthModeOAuth,
			header:   "Bearer " + key,
			want:     key, wantOK: true,
		},
		{
			name:     "apikey accepts Bearer",
			authMode: config.AuthModeAPIKey,
			header:   "Bearer " + key,
			want:     key, wantOK: true,
		},

		// Only API key mode accepts a bare credential.
		{
			name:     "apikey accepts a bare credential",
			authMode: config.AuthModeAPIKey,
			header:   key,
			want:     key, wantOK: true,
		},
		{
			// Loosening this for OAuth would change behaviour for the deployment
			// this server was written for, where the MCP spec requires the scheme.
			name:     "oauth rejects a bare credential",
			authMode: config.AuthModeOAuth,
			header:   key,
			wantOK:   false,
		},

		// Neither mode accepts a different scheme, in either mode. Requiring the
		// bare form to contain no space is what keeps these distinguishable.
		{
			name:     "apikey rejects Basic",
			authMode: config.AuthModeAPIKey,
			header:   "Basic dXNlcjpwYXNzd29yZA==",
			wantOK:   false,
		},
		{
			name:     "apikey rejects an unknown scheme",
			authMode: config.AuthModeAPIKey,
			header:   "Token " + key,
			wantOK:   false,
		},
		{
			name:     "apikey rejects an empty header",
			authMode: config.AuthModeAPIKey,
			header:   "",
			wantOK:   false,
		},
		{
			name:     "oauth rejects an empty header",
			authMode: config.AuthModeOAuth,
			header:   "",
			wantOK:   false,
		},
		{
			// "Bearer" with nothing after it must not resolve to an empty
			// credential that then gets sent to Teamwork API.
			name:     "bearer with no token is rejected",
			authMode: config.AuthModeAPIKey,
			header:   "Bearer ",
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resources config.Resources
			resources.Info.AuthMode = tt.authMode

			got, ok := extractCredential(resources, tt.header)
			if ok != tt.wantOK {
				t.Fatalf("extractCredential(%q) ok = %v, want %v", tt.header, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("extractCredential(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}
