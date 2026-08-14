package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/teamwork/mcp/pkg/config"
)

// apiKeyScopes is the scope set granted to an API key.
//
// A Teamwork Projects API key carries no scopes of its own — unlike an OAuth
// token, there is nothing in the credential or in the userinfo response to
// enumerate. It authenticates against the Projects v3 API only: Desk
// (/desk/api/v2) and Spaces (/spaces/api/v1) answer 401 for the same key,
// because those are separately licensed products with their own credentials.
//
// Reporting "projects" alone is therefore not a policy choice but a statement
// of fact about what the key can reach, and it is load-bearing: the receiving
// middleware in pkg/config filters tools/list by these scopes on the tool
// name prefix, so twdesk/twspaces/twchat tools are never advertised to a client
// authenticated this way. Without it the model would see tools whose every call
// returns 401.
var apiKeyScopes = []string{"projects"}

// GetAPIKeyInfo resolves a Teamwork Projects API key into the same BearerInfo
// the OAuth path produces, so everything downstream of authentication is
// identical for both credential types.
//
// It deliberately does not use /launchpad/v1/userinfo.json, the endpoint
// GetBearerInfo calls. Launchpad is Teamwork's identity service and answers 401
// for an API key regardless of whether the key is sent as a bearer token or as
// basic auth — an installation that does not use Launchpad has no identity there
// to resolve. /projects/api/v3/me.json is the equivalent probe on the API the
// key does authenticate against: it is cheap, read-only, and returns the
// installation ID the request logger and tracer need.
//
// Two consequences of that substitution are worth stating, because they shape
// the configuration this function requires:
//
// Basic auth, not bearer. The Projects API accepts an API key as the username
// of an HTTP Basic credential with any non-empty password; the same key sent as
// "Authorization: Bearer" is rejected with 401. This mirrors
// session.NewBasicAuth, which the caller must use to build the SDK session for
// the same reason.
//
// The site URL comes from configuration. me.json returns no installation URL
// (and no AWS region), so unlike the OAuth path there is nothing to discover the
// host from. Requests must go to the customer's own site — for a region-hosted
// installation the global teamwork.com default is simply wrong — so
// resources.Info.SiteURL is required whenever this path is in use, and is
// validated at startup rather than per request.
func GetAPIKeyInfo(ctx context.Context, resources config.Resources, apiKey string) (*BearerInfo, error) {
	url := resources.Info.SiteURL + "/projects/api/v3/me.json"

	authRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth request: %w", err)
	}
	// The password is ignored by the API but must be present for the header to
	// be well-formed basic auth.
	authRequest.SetBasicAuth(apiKey, "x")

	response, err := resources.TeamworkHTTPClient().Do(authRequest)
	if err != nil {
		// Same distinction GetBearerInfo draws: a cancelled caller context means
		// the MCP client hung up and is routine, while a transport failure means
		// we could not reach Teamwork API and is worth alerting on.
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("%w: %w", ErrBearerInfoCanceled, err)
		}
		return nil, fmt.Errorf("%w: failed to perform auth request: %w", ErrBearerInfoUnavailable, err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			resources.Logger().ErrorContext(ctx, "failed to close auth response body",
				slog.String("error", err.Error()),
			)
		}
	}()

	// classifyAuthStatus is shared with the OAuth path: only 401 and 403 mean the
	// credential was refused, and every other non-200 must stay distinguishable
	// so a momentary upstream failure is never reported to the client as an
	// invalid key.
	if err := classifyAuthStatus(response.StatusCode, url); err != nil {
		return nil, err
	}

	// me.json nests the user under "person" — see projects.UserGetMeResponse in
	// twapi-go-sdk, which models the same envelope.
	var body struct {
		Person struct {
			ID             int64  `json:"id"`
			InstallationID int64  `json:"installationId"`
			EmailAddress   string `json:"emailAddress"`
		} `json:"person"`
	}

	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&body); err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("%w: %w", ErrBearerInfoCanceled, err)
		}
		return nil, fmt.Errorf("%w: failed to decode auth response: %w", ErrBearerInfoUnavailable, err)
	}

	// A 200 carrying no user id means we authenticated against something that is
	// not the endpoint we expect — a login page or an interstitial proxy will
	// happily return 200 with a body that decodes to zero values. Treat it as a
	// refusal rather than letting an unidentified request through.
	if body.Person.ID == 0 {
		return nil, fmt.Errorf("%w: no user in response from %s", ErrBearerInfoUnauthorized, url)
	}

	info := &BearerInfo{
		UserID:         body.Person.ID,
		InstallationID: body.Person.InstallationID,
		URL:            resources.Info.SiteURL,
		// me.json reports no region. Echoing the configured region keeps the
		// caller's cross-region comparison false, which is the correct answer
		// for a single-installation deployment: cross-region only suppresses
		// HAProxy routing, and this path does not run behind one.
		Region: resources.Info.AWSRegion,
	}
	info.Meta.Scopes = apiKeyScopes
	return info, nil
}
