package auth_test

import (
	"github.com/usepassflow/go/auth"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProtectedResourceRegistrationErrors(t *testing.T) {
	const issuer = "https://auth.example.com"
	const resource = "https://notes.example/mcp"
	cfg := auth.Config{Issuer: issuer}
	for _, v := range []string{"", "http://notes.example/mcp", resource + "#fragment", "https://user@notes.example/mcp"} {
		if _, err := auth.NewProtectedResource(cfg, auth.ProtectedResourceConfig{Resource: v}); err == nil {
			t.Errorf("accepted %q", v)
		}
	}
	p, err := auth.NewProtectedResource(cfg, auth.ProtectedResourceConfig{Resource: resource})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"", "two words", "quote\"", "back\\slash", "read\nwrite"} {
		t.Run(s, func(t *testing.T) {
			if _, err := auth.NewProtectedResource(cfg, auth.ProtectedResourceConfig{Resource: resource, Scopes: []string{s}}); err == nil {
				t.Error("accepted invalid default scope")
			}
			defer func() {
				if recover() == nil {
					t.Error("accepted invalid route scope")
				}
			}()
			p.RequireScopes(s)
		})
	}
	cfg.Audiences = []string{"app"}
	if _, err := auth.NewProtectedResource(cfg, auth.ProtectedResourceConfig{Resource: resource}); err == nil {
		t.Error("accepted second audience configuration")
	}
}

func TestResourceStepUpAndTokenClaims(t *testing.T) {
	const issuer = "https://auth.example.com"
	const resource = "https://notes.example/mcp"
	const userinfo = issuer + "/oidc/userinfo"
	const suffix = `, resource_metadata="https://notes.example/.well-known/oauth-protected-resource/mcp"`
	key := generateTestKey(t, "EC", "resource", 256)
	h := newJWKSHarness(t, key)
	p, err := auth.NewProtectedResource(auth.Config{Issuer: issuer, JWKSURL: h.server.URL + "/jwks", Now: h.now}, auth.ProtectedResourceConfig{Resource: resource, Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	request := func(handler http.Handler, aud []string, typ string, scope any) *httptest.ResponseRecorder {
		c := happyClaims()
		c["acr"] = "1"
		c["aud"] = aud
		c["scopes"] = []string{"read"}
		if scope == nil {
			delete(c, "scope")
		} else {
			c["scope"] = scope
		}
		header := map[string]any{}
		if typ != "" {
			header["typ"] = typ
		}
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+signToken(t, key, c, header))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	for _, tc := range []struct {
		handler http.Handler
		param   string
	}{{auth.Require(auth.AAL2)(ok), `acr_values="2"`}, {auth.RequireFresh(time.Second)(ok), "max_age=1"}} {
		w := request(p.Authenticate(tc.handler), []string{resource, userinfo}, "JWT", "read")
		want := `Bearer error="insufficient_user_authentication", ` + tc.param + suffix
		if w.Code != 401 || w.Header().Get("WWW-Authenticate") != want {
			t.Errorf("step-up: %d %q; want 401 %q", w.Code, w.Header().Get("WWW-Authenticate"), want)
		}
	}
	route := p.RequireScopes("read")(ok)
	for _, tc := range []struct {
		typ    string
		aud    []string
		scope  any
		status int
	}{
		{"", []string{resource, userinfo}, nil, 204}, {"jWt", []string{userinfo, resource}, "read", 204}, {"At+Jwt", []string{resource}, "read", 204}, {"APPLICATION/AT+JWT", []string{resource}, "read", 204}, {"opaque", []string{resource}, "read", 401}, {"JWT", []string{userinfo}, "read", 401}, {"JWT", []string{"https://other.example", userinfo}, "read", 401}, {"JWT", []string{resource}, "", 403}, {"JWT", []string{resource}, []string{"read"}, 403},
	} {
		if w := request(route, tc.aud, tc.typ, tc.scope); w.Code != tc.status {
			t.Errorf("typ=%q aud=%v scope=%v: %d, want %d", tc.typ, tc.aud, tc.scope, w.Code, tc.status)
		}
	}
}
