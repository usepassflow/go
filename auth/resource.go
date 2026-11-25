package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	metadataWellKnown  = "/.well-known/oauth-protected-resource"
	metadataMethods    = "GET, HEAD, OPTIONS"
	maxResourceBytes   = 2048
	scopeOfflineAccess = "offline_access"
)

var (
	// resourcePattern splits a resource into its origin, path and query. It admits no userinfo and no
	// fragment, and nothing that needs escaping in a quoted challenge parameter.
	resourcePattern = regexp.MustCompile(`^((?i:https?)://(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+)(?::[0-9]{1,5})?)` +
		`(/(?:[A-Za-z0-9._~:/@!$&'()*+,;=-]|%[0-9A-Fa-f]{2})*)?` +
		`(\?(?:[A-Za-z0-9._~:/?@!$&'()*+,;=-]|%[0-9A-Fa-f]{2})*)?$`)
	// scopeTokenPattern is the scope-token of RFC 6749, section 3.3.
	scopeTokenPattern = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`)
)

// ProtectedResourceConfig describes an OAuth protected resource, such as an MCP server.
type ProtectedResourceConfig struct {
	// Resource is the exact URL clients name as the resource, and the audience a token must carry.
	// It must use https unless the host is loopback, with no userinfo and no fragment.
	Resource string
	// Scopes are the scopes a client needs to start. The 401 challenge and scopes_supported list
	// them. offline_access is not a scope of a resource and is rejected.
	Scopes []string
	// Name is served as resource_name. Optional.
	Name string
}

// ProtectedResource is a [Verifier] for one resource, with the RFC 9728 metadata that tells a client
// where to get a token. It is safe for concurrent use.
type ProtectedResource struct {
	verifier     *Verifier
	metadataPath string
	metadata     []byte
}

// resourceMetadata is the RFC 9728 document.
type resourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name,omitempty"`
}

// NewProtectedResource validates a configuration and makes no network call. The resource is the only
// audience, so cfg.Audiences must be empty. A rejection names the option, as [NewVerifier] does, with
// resource and scopes for the options of rc.
func NewProtectedResource(cfg Config, rc ProtectedResourceConfig) (*ProtectedResource, error) {
	if len(cfg.Audiences) != 0 {
		return nil, configError("audiences", "Audiences must be empty: the audience is the resource")
	}
	origin, path, query, err := splitResource(rc.Resource)
	if err != nil {
		return nil, err
	}
	for _, scope := range rc.Scopes {
		if !scopeTokenPattern.MatchString(scope) {
			return nil, configError("scopes", "Scopes must hold RFC 6749 scope tokens")
		}
		if scope == scopeOfflineAccess {
			return nil, configError("scopes", "Scopes must not hold offline_access")
		}
	}

	cfg.Audiences = []string{rc.Resource}
	verifier, err := NewVerifier(cfg)
	if err != nil {
		return nil, err
	}
	metadataPath := metadataWellKnown
	if path != "/" {
		metadataPath += path
	}
	verifier.resource = &resourceChallenge{
		scope:    strings.Join(rc.Scopes, " "),
		metadata: origin + metadataPath + query,
	}

	var document bytes.Buffer
	encoder := json.NewEncoder(&document)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(resourceMetadata{
		Resource:               rc.Resource,
		AuthorizationServers:   []string{cfg.Issuer},
		ScopesSupported:        rc.Scopes,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           rc.Name,
	}); err != nil {
		return nil, err
	}
	return &ProtectedResource{verifier: verifier, metadataPath: metadataPath, metadata: document.Bytes()}, nil
}

// Verifier returns the resource's verifier. Its middleware answers with the resource's challenges.
func (p *ProtectedResource) Verifier() *Verifier {
	return p.verifier
}

// MetadataPath is the path of the metadata URL the challenges name: the well-known path, followed by
// the path of the resource if it has one.
func (p *ProtectedResource) MetadataPath() string {
	return p.metadataPath
}

// MetadataHandler serves the metadata document to any origin. Mount it on every method of
// [ProtectedResource.MetadataPath], because a browser client may send a preflight request.
func (p *ProtectedResource) MetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Access-Control-Allow-Origin", "*")
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			header.Set("Content-Type", "application/json")
			header.Set(headerCacheControl, "max-age=300")
			header.Set("Content-Length", strconv.Itoa(len(p.metadata)))
			if r.Method == http.MethodGet {
				_, _ = w.Write(p.metadata)
			}
		case http.MethodOptions:
			header.Set("Access-Control-Allow-Methods", metadataMethods)
			header.Set("Access-Control-Allow-Headers", "*")
			w.WriteHeader(http.StatusNoContent)
		default:
			header.Set("Allow", metadataMethods)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

// Authenticate is [Verifier.Authenticate] with the resource's challenges. The package-level [Require]
// and [RequireFresh] behind it name the resource metadata too.
func (p *ProtectedResource) Authenticate(next http.Handler) http.Handler {
	return p.verifier.Authenticate(next)
}

// RequireScopes answers 403 insufficient_scope unless the token carries every scope. It authenticates
// on demand, with the same rule for claims as [Verifier.Require]. It panics at construction without
// a scope, or on one that is not an RFC 6749 scope token.
//
// It checks what the user delegated to the client, not what the user may do: the user's own
// permissions stay the handler's check.
func (p *ProtectedResource) RequireScopes(scopes ...string) func(http.Handler) http.Handler {
	if len(scopes) == 0 {
		panic("passflow auth: RequireScopes needs at least one scope")
	}
	for _, scope := range scopes {
		if !scopeTokenPattern.MatchString(scope) {
			panic("passflow auth: RequireScopes needs RFC 6749 scope tokens")
		}
	}
	required := slices.Clone(scopes)
	challenge := p.verifier.resource.insufficientScope(required)
	return p.verifier.onDemand(func(w http.ResponseWriter, c *Claims) bool {
		if c.HasScopes(required...) {
			return true
		}
		writeRejection(w, http.StatusForbidden, challenge)
		return false
	})
}

// splitResource validates a resource URL. The error states the rule and never the URL.
func splitResource(raw string) (origin, path, query string, err error) {
	parts := resourcePattern.FindStringSubmatch(raw)
	if parts == nil || len(raw) > maxResourceBytes {
		return "", "", "", configError("resource",
			"Resource must be an absolute http or https URL of at most 2048 bytes, without userinfo or a fragment")
	}
	u, parseErr := url.Parse(raw)
	if parseErr != nil {
		return "", "", "", configError("resource", "Resource must be a valid URL")
	}
	if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		return "", "", "", configError("resource", "Resource must use https unless the host is loopback")
	}
	return parts[1], parts[2], parts[3], nil
}

// resourceChallenge writes the challenges of a protected resource, with the parameter order error,
// scope, resource_metadata. On nil, a challenge stays as given. Scopes and the URL were validated, so
// nothing needs escaping.
type resourceChallenge struct {
	scope    string // space-separated; empty is omitted
	metadata string // the metadata URL
}

func (c *resourceChallenge) unauthorized(challenge string) string {
	if c == nil {
		return challenge
	}
	if c.scope != "" {
		challenge = addParameter(challenge, "scope", c.scope)
	}
	return addParameter(challenge, "resource_metadata", c.metadata)
}

func (c *resourceChallenge) insufficientScope(required []string) string {
	challenge := addParameter(challengeScope, "scope", strings.Join(required, " "))
	return addParameter(challenge, "resource_metadata", c.metadata)
}

func (c *resourceChallenge) stepUp(challenge string) string {
	if c == nil {
		return challenge
	}
	return addParameter(challenge, "resource_metadata", c.metadata)
}

func addParameter(challenge, name, value string) string {
	separator := ", "
	if challenge == challengeMissingToken {
		separator = " "
	}
	return challenge + separator + name + `="` + value + `"`
}
