package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/teamwork/mcp/internal/config"
)

// meJSONBody mirrors the envelope Teamwork API actually returns from
// /projects/api/v3/me.json — the user is nested under "person", matching
// projects.UserGetMeResponse in twapi-go-sdk.
const meJSONBody = `{
  "person": {
    "id": 254696,
    "firstName": "Test",
    "lastName": "User",
    "emailAddress": "test@example.com",
    "companyId": 114375,
    "installationId": 1064643
  }
}`

// newAPIKeyResources points a real config.Resources at a test server, so these
// tests exercise the same HTTP client the server uses in production rather than
// a substitute.
func newAPIKeyResources(t *testing.T, siteURL string) config.Resources {
	t.Helper()
	t.Setenv("TW_MCP_AUTH_MODE", config.AuthModeAPIKey)
	t.Setenv("TW_MCP_SITE_URL", siteURL)
	resources, teardown := config.Load(io.Discard)
	t.Cleanup(teardown)
	return resources
}

func TestGetAPIKeyInfo(t *testing.T) {
	var gotPath, gotAuthHeader, gotUsername, gotPassword string
	var gotBasicAuthOK bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuthHeader = r.Header.Get("Authorization")
		gotUsername, gotPassword, gotBasicAuthOK = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(meJSONBody))
	}))
	defer server.Close()

	resources := newAPIKeyResources(t, server.URL)

	info, err := GetAPIKeyInfo(context.Background(), resources, "twp_testkey_eu")
	if err != nil {
		t.Fatalf("GetAPIKeyInfo() = %v, want nil", err)
	}

	// The endpoint must be the Projects probe, not the Launchpad one. An
	// installation without Launchpad answers 401 there for any API key, so
	// reverting to it would break this path entirely.
	if want := "/projects/api/v3/me.json"; gotPath != want {
		t.Errorf("requested path = %q, want %q", gotPath, want)
	}

	// The credential must travel as basic auth. This is the single reason this
	// function exists rather than reusing GetBearerInfo: Teamwork API rejects an
	// API key presented as a bearer token.
	if !gotBasicAuthOK {
		t.Fatalf("Authorization header %q is not basic auth", gotAuthHeader)
	}
	if want := "twp_testkey_eu"; gotUsername != want {
		t.Errorf("basic auth username = %q, want the API key %q", gotUsername, want)
	}
	if gotPassword == "" {
		t.Error("basic auth password is empty; the header must be well-formed")
	}

	if info.UserID != 254696 {
		t.Errorf("UserID = %d, want 254696", info.UserID)
	}
	if info.InstallationID != 1064643 {
		t.Errorf("InstallationID = %d, want 1064643", info.InstallationID)
	}
	// me.json carries no installation URL, so it has to come from configuration.
	if info.URL != server.URL {
		t.Errorf("URL = %q, want the configured site URL %q", info.URL, server.URL)
	}
}

// TestGetAPIKeyInfoGrantsOnlyProjectsScope is the guard on tool filtering. The
// receiving middleware in internal/config removes twdesk/twspaces/twchat tools
// unless the matching scope is present, and an API key cannot authenticate
// against those products. Widening this would advertise tools whose every call
// returns 401.
func TestGetAPIKeyInfoGrantsOnlyProjectsScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(meJSONBody))
	}))
	defer server.Close()

	resources := newAPIKeyResources(t, server.URL)

	info, err := GetAPIKeyInfo(context.Background(), resources, "twp_testkey_eu")
	if err != nil {
		t.Fatalf("GetAPIKeyInfo() = %v, want nil", err)
	}
	if want := []string{"projects"}; !slices.Equal(info.Meta.Scopes, want) {
		t.Fatalf("scopes = %v, want exactly %v", info.Meta.Scopes, want)
	}
}

func TestGetAPIKeyInfoStatusHandling(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		want       error
	}{
		{
			name:       "unauthorized is a rejection",
			statusCode: http.StatusUnauthorized,
			body:       `{"errors":["unauthorized"]}`,
			want:       ErrBearerInfoUnauthorized,
		},
		{
			name:       "forbidden is a rejection",
			statusCode: http.StatusForbidden,
			want:       ErrBearerInfoUnauthorized,
		},
		{
			// The invariant inherited from the OAuth path: an outage must never be
			// reported as a bad credential.
			name:       "server error is inconclusive",
			statusCode: http.StatusInternalServerError,
			want:       ErrBearerInfoUnavailable,
		},
		{
			name:       "rate limiting is inconclusive",
			statusCode: http.StatusTooManyRequests,
			want:       ErrBearerInfoUnavailable,
		},
		{
			// A proxy or login interstitial can return 200 with a body that decodes
			// to zero values. Letting that through would admit an unidentified
			// request whose installation ID is 0.
			name:       "a 200 with no user is a rejection",
			statusCode: http.StatusOK,
			body:       `{}`,
			want:       ErrBearerInfoUnauthorized,
		},
		{
			name:       "a 200 with an empty person is a rejection",
			statusCode: http.StatusOK,
			body:       `{"person":{}}`,
			want:       ErrBearerInfoUnauthorized,
		},
		{
			name:       "a 200 with a non-JSON body is inconclusive",
			statusCode: http.StatusOK,
			body:       `<html>login</html>`,
			want:       ErrBearerInfoUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			resources := newAPIKeyResources(t, server.URL)

			_, err := GetAPIKeyInfo(context.Background(), resources, "twp_testkey_eu")
			if !errors.Is(err, tt.want) {
				t.Fatalf("GetAPIKeyInfo() = %v, want %v", err, tt.want)
			}
			// Whatever the failure, it must never be classified as both — the
			// middleware branches on these to decide whether to tell the client its
			// credential is bad.
			if errors.Is(err, ErrBearerInfoUnauthorized) && errors.Is(err, ErrBearerInfoUnavailable) {
				t.Fatalf("GetAPIKeyInfo() = %v, classified as both a rejection and inconclusive", err)
			}
		})
	}
}

// TestGetAPIKeyInfoCanceledContext confirms a client hanging up is reported as
// cancellation rather than as a server error, so it stays out of the error logs.
func TestGetAPIKeyInfoCanceledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(meJSONBody))
	}))
	defer server.Close()

	resources := newAPIKeyResources(t, server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := GetAPIKeyInfo(ctx, resources, "twp_testkey_eu")
	if !errors.Is(err, ErrBearerInfoCanceled) {
		t.Fatalf("GetAPIKeyInfo() = %v, want %v", err, ErrBearerInfoCanceled)
	}
}
