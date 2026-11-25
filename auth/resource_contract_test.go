package auth_test

import (
	"encoding/json"
	"github.com/usepassflow/go/auth"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestProtectedResourceConformance(t *testing.T) {
	const issuer = "https://auth.example.com"
	const resource = "https://api.example/mcp"
	const path = "/.well-known/oauth-protected-resource/mcp"
	const metadata = "https://api.example" + path
	key := generateTestKey(t, "EC", "resource", 256)
	h := newJWKSHarness(t, key)
	cfg := auth.Config{Issuer: issuer, JWKSURL: h.server.URL + "/jwks", Now: h.now}
	rc := auth.ProtectedResourceConfig{Resource: resource, Scopes: []string{"read"}, Name: "Notes"}
	p, e := auth.NewProtectedResource(cfg, rc)
	if e != nil {
		t.Fatal(e)
	}
	if p.MetadataPath() != path {
		t.Fatalf("metadata path = %q", p.MetadataPath())
	}
	w := httptest.NewRecorder()
	p.MetadataHandler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	var doc map[string]any
	if e = json.Unmarshal(w.Body.Bytes(), &doc); e != nil {
		t.Fatal(e)
	}
	for k, v := range map[string]any{"resource": resource, "authorization_servers": []any{issuer}, "scopes_supported": []any{"read"}, "resource_name": "Notes", "bearer_methods_supported": []any{"header"}} {
		if !reflect.DeepEqual(v, doc[k]) {
			t.Errorf("%s = %v, want %v", k, doc[k], v)
		}
	}
	if w.Code != 200 || w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal(w.Result().Status, w.Header())
	}
	rc.Scopes = []string{"offline_access"}
	if _, err := auth.NewProtectedResource(cfg, rc); err == nil {
		t.Error("offline_access accepted as a resource scope")
	}
	const tail = `resource_metadata="` + metadata + `"`
	for _, tc := range []struct {
		name, typ string
		scope     any
		aud       string
		status    int
		challenge string
	}{
		{"missing", "", nil, resource, 401, `Bearer scope="read", ` + tail},
		{"wrong audience", "at+jwt", "read write", "https://other.example", 401, `Bearer error="invalid_token", scope="read", ` + tail},
		{"wrong typ", "opaque", "read write", resource, 401, `Bearer error="invalid_token", scope="read", ` + tail},
		{"scope string wins", "JWT", "read", resource, 403, `Bearer error="insufficient_scope", scope="read write", ` + tail},
		{"wrong scope type", "JWT", []string{"read", "write"}, resource, 403, `Bearer error="insufficient_scope", scope="read write", ` + tail},
		{"at jwt", "at+jwt", "read write", resource, 204, ""}, {"legacy array", "application/at+jwt", nil, resource, 204, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/notes", nil)
			if tc.name != "missing" {
				c := happyClaims()
				c["aud"] = []string{tc.aud, issuer + "/oidc/userinfo"}
				c["scopes"] = []string{"read", "write"}
				if tc.scope == nil {
					delete(c, "scope")
				} else {
					c["scope"] = tc.scope
				}
				req.Header.Set("Authorization", "Bearer "+signToken(t, key, c, map[string]any{"typ": tc.typ}))
			}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				claims, ok := auth.ClaimsFromContext(r.Context())
				if !ok || !claims.HasScopes("read", "write") || claims.HasScopes("delete") {
					t.Error("unexpected delegated scopes")
				}
				w.WriteHeader(204)
			})
			out := httptest.NewRecorder()
			p.Authenticate(p.RequireScopes("read", "write")(next)).ServeHTTP(out, req)
			if out.Code != tc.status || out.Header().Get("WWW-Authenticate") != tc.challenge {
				t.Fatalf("got %d %q, want %d %q", out.Code, out.Header().Get("WWW-Authenticate"), tc.status, tc.challenge)
			}
		})
	}
}
