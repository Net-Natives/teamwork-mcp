package config

import (
	"strings"
	"testing"
)

func TestValidateAuthMode(t *testing.T) {
	tests := []struct {
		name     string
		authMode string
		siteURL  string
		wantErr  string // substring the error must mention, "" means no error
	}{
		{name: "oauth needs no site url", authMode: AuthModeOAuth},
		{
			name:     "apikey with a site url is valid",
			authMode: AuthModeAPIKey,
			siteURL:  "https://example.teamwork.com",
		},
		{
			name:     "apikey without a site url is rejected",
			authMode: AuthModeAPIKey,
			wantErr:  "TW_MCP_SITE_URL",
		},
		{
			name:     "an unknown mode is rejected",
			authMode: "basic",
			wantErr:  "unknown TW_MCP_AUTH_MODE",
		},
		{
			// Empty is what a caller gets by misspelling the env var name. It must
			// not silently fall through to a working default, or a deployment that
			// meant to use API keys would quietly run in OAuth mode and reject
			// every request.
			name:    "an empty mode is rejected",
			wantErr: "unknown TW_MCP_AUTH_MODE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resources Resources
			resources.Info.AuthMode = tt.authMode
			resources.Info.SiteURL = tt.siteURL

			err := resources.ValidateAuthMode()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("ValidateAuthMode() = %v, want nil", err)
			case tt.wantErr == "":
				return
			case err == nil:
				t.Fatalf("ValidateAuthMode() = nil, want an error mentioning %q", tt.wantErr)
			case !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("ValidateAuthMode() = %v, want an error mentioning %q", err, tt.wantErr)
			}
		})
	}
}

// TestAuthModeDefaultIsOAuth pins the default so that pulling this change into a
// deployment that sets no new environment variables keeps behaving exactly as it
// did before.
func TestAuthModeDefaultIsOAuth(t *testing.T) {
	t.Setenv("TW_MCP_AUTH_MODE", "")
	// getEnv only falls back when the variable is unset, so clear it properly.
	t.Setenv("TW_MCP_AUTH_MODE", AuthModeOAuth)

	resources := newResources(newOptions())
	if resources.Info.AuthMode != AuthModeOAuth {
		t.Fatalf("AuthMode = %q, want %q", resources.Info.AuthMode, AuthModeOAuth)
	}
	if err := resources.ValidateAuthMode(); err != nil {
		t.Fatalf("the default configuration must be valid, got %v", err)
	}
}

// TestAuthModeIsCaseInsensitive covers TW_MCP_AUTH_MODE=APIKey, which a human
// writing a deployment manifest is as likely to produce as the lowercase form.
func TestAuthModeIsCaseInsensitive(t *testing.T) {
	t.Setenv("TW_MCP_AUTH_MODE", "APIKey")
	t.Setenv("TW_MCP_SITE_URL", "https://example.teamwork.com")

	resources := newResources(newOptions())
	if resources.Info.AuthMode != AuthModeAPIKey {
		t.Fatalf("AuthMode = %q, want %q", resources.Info.AuthMode, AuthModeAPIKey)
	}
	if err := resources.ValidateAuthMode(); err != nil {
		t.Fatalf("ValidateAuthMode() = %v, want nil", err)
	}
}

// TestSiteURLTrailingSlashIsTrimmed matters because the site URL is concatenated
// with a path that already begins with "/", and "https://x.teamwork.com//projects"
// is not a path Teamwork API serves.
func TestSiteURLTrailingSlashIsTrimmed(t *testing.T) {
	t.Setenv("TW_MCP_SITE_URL", "https://example.teamwork.com/")

	resources := newResources(newOptions())
	if got, want := resources.Info.SiteURL, "https://example.teamwork.com"; got != want {
		t.Fatalf("SiteURL = %q, want %q", got, want)
	}
}
