// Package mcphttp carries the HTTP plumbing an MCP server needs around the
// protocol handler: the middleware chain, the health and RFC 9728 metadata
// endpoints, and the bearer-token authentication that turns a token into the
// per-request values tool handlers read.
//
// It lives here rather than in a server's main package because a main package
// cannot be imported. Authentication especially must not be forked: two copies
// drift, and the one that drifts is the one that stops rejecting what it should.
package mcphttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/teamwork/mcp/pkg/auth"
	"github.com/teamwork/mcp/pkg/config"
	"github.com/teamwork/mcp/pkg/request"
	"github.com/teamwork/mcp/pkg/twctx"
	"github.com/teamwork/twapi-go-sdk/session"
)

var reBearerToken = regexp.MustCompile(`^Bearer (.+)$`)

// Auth authenticates every request with a bearer token, rejecting the ones that
// carry no usable credential and populating the context of the ones that do.
//
// Unauthenticated paths are the ones that cannot require a token: health checks,
// browser favicon probes, and the /.well-known OAuth metadata an unauthorised
// client fetches to discover where to authorise. A request with no
// Authorization header on any other path is allowed through only when its JSON
// body names a protocol method auth.Bypass whitelists, which is how a client
// negotiates capabilities before it holds a token.
func Auth(resources config.Resources, validator *auth.Validator, next http.Handler) http.Handler {
	whitelistEndpoints := map[string][]string{
		// health checks don't require authentication
		"/api/health": {http.MethodGet, http.MethodOptions},
		// browser may request favicons without authentication
		"/favicon.ico": {http.MethodGet, http.MethodOptions},
	}

	whitelistPrefixEndpoints := map[string][]string{
		// OAuth2 endpoints cannot require authentication
		"/.well-known": {http.MethodGet, http.MethodOptions},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestLogger := resources.Logger().With(
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("query", r.URL.RawQuery),
		)

		if r.Header.Get("Authorization") == "" {
			// some endpoints don't require auth

			if methods, ok := whitelistEndpoints[r.URL.Path]; ok && slices.Contains(methods, r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			for prefix, methods := range whitelistPrefixEndpoints {
				if strings.HasPrefix(r.URL.Path, prefix) && slices.Contains(methods, r.Method) {
					next.ServeHTTP(w, r)
					return
				}
			}

			content, err := io.ReadAll(r.Body)
			if err != nil {
				requestLogger.ErrorContext(r.Context(), "failed to read request body",
					slog.String("error", err.Error()),
				)
				http.Error(w, "Failed to read request body", http.StatusInternalServerError)
				return
			}

			bypass, err := auth.Bypass(content)
			switch {
			case err != nil, !bypass:
				challenge(w, resources)
			default:
				r.Body = io.NopCloser(bytes.NewBuffer(content))
				next.ServeHTTP(w, r)
			}
			return
		}

		bearerToken, ok := extractCredential(resources, r.Header.Get("Authorization"))
		if !ok {
			challenge(w, resources)
			return
		}

		info, err := authenticateCredential(r.Context(), resources, validator, bearerToken)
		switch {
		case errors.Is(err, auth.ErrBearerInfoUnauthorized):
			// The token was positively rejected, so challenge the client to
			// re-authorise.
			challenge(w, resources)
			return

		case errors.Is(err, auth.ErrBearerInfoCanceled):
			// The client hung up while we were validating. Nobody is left to
			// read a response and nothing failed on our side, so this is debug
			// noise rather than an error.
			requestLogger.DebugContext(r.Context(), "bearer info validation canceled by client",
				slog.String("error", err.Error()),
			)
			return

		case errors.Is(err, auth.ErrBearerInfoUnavailable):
			// We could not determine whether the token is valid. Never send a
			// re-authorisation challenge here: the token is probably fine, and
			// telling the client to discard it puts the user through the whole
			// OAuth flow (and MFA) over what may be a momentary blip.
			requestLogger.ErrorContext(r.Context(), "failed to validate bearer info",
				slog.String("error", err.Error()),
			)
			http.Error(w, "Failed to validate bearer token", http.StatusServiceUnavailable)
			return

		case err != nil:
			requestLogger.ErrorContext(r.Context(), "failed to get bearer info",
				slog.String("error", err.Error()),
			)
			http.Error(w, "Failed to get bearer info", http.StatusInternalServerError)
			return
		}

		if span, ok := tracer.SpanFromContext(r.Context()); ok {
			span.SetTag("user.id", info.UserID)
			span.SetTag("installation.id", info.InstallationID)
			span.SetTag("installation.url", info.URL)
		}
		if requestInfo, ok := request.InfoFromContext(r.Context()); ok {
			requestInfo.SetAuth(info.InstallationID, info.URL, info.UserID)
		}

		ctx := r.Context()
		// detect cross-region requests
		ctx = twctx.WithCrossRegion(ctx, !strings.EqualFold(resources.Info.AWSRegion, info.Region))
		// inject customer URL
		ctx = twctx.WithCustomerURL(ctx, info.URL)
		// inject bearer token
		ctx = twctx.WithBearerToken(ctx, bearerToken)
		// inject scopes
		ctx = twctx.WithScopes(ctx, info.Meta.Scopes)
		// restrict responses for the configured installations
		ctx = twctx.WithRestrictedData(ctx, resources.IsRestrictedInstallation(info.InstallationID))
		// inject session
		ctx = session.WithBearerTokenContext(ctx, session.NewBearerToken(bearerToken, info.URL))

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractCredential pulls the credential out of an Authorization header value.
//
// OAuth mode accepts only the "Bearer <token>" form, exactly as before: that is
// what the MCP specification requires, and loosening it would change behaviour
// for the deployment this server was written for.
//
// API key mode additionally accepts a bare value with no scheme, because the two
// Claude surfaces that send a static credential disagree about who adds the
// scheme. The Messages API takes mcp_servers[].authorization_token as a raw
// token and sends "Authorization: Bearer <token>" itself, so the value must not
// include the prefix. A claude.ai custom connector Request header is sent
// verbatim — its documentation is explicit that Claude "does not add an
// authentication scheme or any other prefix" — so there the value must include
// it. The same key is therefore correct in one place and wrong in the other, and
// getting it wrong produces a 401 indistinguishable from an invalid key.
// Accepting both removes a whole class of unfixable-looking misconfiguration.
//
// A value containing a space is still rejected, so a genuinely different scheme
// ("Basic dXNlcjpwYXNz") is never mistaken for a bare API key.
func extractCredential(resources config.Resources, header string) (string, bool) {
	if matches := reBearerToken.FindStringSubmatch(header); len(matches) >= 2 {
		return matches[1], true
	}
	if resources.Info.AuthMode == config.AuthModeAPIKey && header != "" && !strings.Contains(header, " ") {
		return header, true
	}
	return "", false
}

// authenticateCredential resolves the credential from the Authorization header
// into a BearerInfo, using whichever validation the configured auth mode
// requires. Both paths return the same type and the same sentinel errors, so
// everything downstream — logging, tracing, scopes, the session — is identical.
func authenticateCredential(
	ctx context.Context,
	resources config.Resources,
	validator *auth.Validator,
	credential string,
) (*auth.BearerInfo, error) {
	if resources.Info.AuthMode == config.AuthModeAPIKey {
		return auth.GetAPIKeyInfo(ctx, resources, credential)
	}
	return validator.GetBearerInfo(ctx, credential)
}

// challenge answers 401 with the RFC 9728 pointer to this server's
// protected-resource metadata, which is how a client learns where to authorise.
// Only send it when the token was actually refused — it makes the client throw
// its token away.
//
// In API key mode the pointer is deliberately left out and the 401 is bare. The
// metadata names Teamwork's authorization server — a flow an API key deployment
// has no part in, and which an installation without Launchpad cannot complete at
// all. Sending it there would invite a client to abandon a perfectly good key and
// start an authorization flow that cannot succeed, turning a fixable "wrong key"
// into an unrecoverable loop.
//
// https://datatracker.ietf.org/doc/html/rfc9728#name-www-authenticate-response
func challenge(w http.ResponseWriter, resources config.Resources) {
	if resources.Info.AuthMode != config.AuthModeAPIKey {
		w.Header().Set("WWW-Authenticate",
			`Bearer resource_metadata="`+ProtectedResourceURL(resources.Info.MCPURL)+`"`)
	}
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}
