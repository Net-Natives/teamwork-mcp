package mcphttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/teamwork/mcp/pkg/config"
)

// TestChallengeOmittedInAPIKeyMode pins that a refused credential in API key
// mode gets a bare 401. The RFC 9728 challenge points at an OAuth flow an API
// key deployment cannot complete, so sending it would turn a fixable bad key
// into an unrecoverable re-authorisation loop. OAuth mode keeps the challenge.
func TestChallengeOmittedInAPIKeyMode(t *testing.T) {
	tests := []struct {
		authMode      string
		wantChallenge bool
	}{
		{authMode: config.AuthModeOAuth, wantChallenge: true},
		{authMode: config.AuthModeAPIKey, wantChallenge: false},
	}
	for _, tt := range tests {
		t.Run(tt.authMode, func(t *testing.T) {
			var resources config.Resources
			resources.Info.AuthMode = tt.authMode
			resources.Info.MCPURL = "https://mcp.example.com"

			rec := httptest.NewRecorder()
			challenge(rec, resources)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
			got := rec.Header().Get("WWW-Authenticate") != ""
			if got != tt.wantChallenge {
				t.Fatalf("WWW-Authenticate present = %v, want %v", got, tt.wantChallenge)
			}
		})
	}
}
