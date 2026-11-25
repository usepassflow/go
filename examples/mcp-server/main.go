// Command mcp-server is an MCP server whose users sign in with Passflow. See README.md.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usepassflow/go/auth"
)

const (
	mcpPath       = "/mcp"
	rootMetadata  = "/.well-known/oauth-protected-resource"
	scopeMCP      = "mcp"
	scopeWrite    = "notes:write"
	maxNoteBytes  = 1000
	maxNotes      = 100
	headerTimeout = 5 * time.Second
)

var errNoClaims = errors.New("the request carries no verified token")

func main() {
	handler, err := newHandler(os.Getenv("PASSFLOW_ISSUER"), os.Getenv("MCP_RESOURCE"), os.Getenv("MCP_WRITERS"))
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:              cmp.Or(os.Getenv("MCP_ADDR"), "localhost:8090"),
		Handler:           handler,
		ReadHeaderTimeout: headerTimeout,
	}
	log.Print("MCP server starting")
	log.Fatal(server.ListenAndServe())
}

func newHandler(issuer, resourceURL, writers string) (http.Handler, error) {
	resource, err := auth.NewProtectedResource(
		auth.Config{Issuer: issuer},
		auth.ProtectedResourceConfig{
			Resource: resourceURL,
			Scopes:   []string{scopeMCP}, // what a client needs to start
			Name:     "Sample notes",
		},
	)
	if err != nil {
		return nil, err
	}
	if resource.MetadataPath() != rootMetadata+mcpPath {
		return nil, errors.New("MCP_RESOURCE must be a URL with the path " + mcpPath)
	}

	n := &notes{
		// FieldsFunc drops empty entries, so an unset MCP_WRITERS lets nobody write.
		writers: strings.FieldsFunc(writers, func(r rune) bool { return r == ',' || r == ' ' }),
		byUser:  make(map[string][]string),
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "passflow-sample-notes", Version: "1.0.0"}, nil)
	closedWorld, additive := false, false
	mcp.AddTool(server, &mcp.Tool{
		Name:        "whoami",
		Description: "Shows who the access token belongs to and what it allows.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, whoami)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "add_note",
		Description: "Adds a note to the signed-in user's notes.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &additive, OpenWorldHint: &closedWorld},
	}, n.add)

	// Stateless: every request is authorized by its own token, and no session outlives it. The context
	// of a tool call carries the values of the HTTP request's context, so the tools read the claims there.
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)

	mux := http.NewServeMux()
	// No method in these patterns: a browser client sends a preflight OPTIONS request first.
	mux.Handle(resource.MetadataPath(), resource.MetadataHandler())
	mux.Handle(rootMetadata, resource.MetadataHandler()) // for clients that try only the root path
	// RequireScopes verifies the token first and puts its claims into the request's context.
	mux.Handle(mcpPath, resource.RequireScopes(scopeMCP)(mcpHandler))
	mux.Handle("GET /notes", resource.RequireScopes(scopeMCP, scopeWrite)(http.HandlerFunc(n.list)))
	return mux, nil
}

type identity struct {
	Subject  string   `json:"sub"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	ACR      string   `json:"acr"`
}

func whoami(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, identity, error) {
	claims, ok := auth.ClaimsFromContext(ctx)
	if !ok {
		return nil, identity{}, errNoClaims
	}
	return nil, identity{
		Subject:  claims.Subject,
		ClientID: claims.ClientID,
		Scopes:   claims.Scopes,
		ACR:      claims.ACR.String(),
	}, nil
}

type noteInput struct {
	Text string `json:"text" jsonschema:"the note, at most 1000 bytes"`
}

type noteCount struct {
	Count int `json:"count"`
}

// notes keeps each user's notes in memory.
type notes struct {
	writers []string

	mu     sync.Mutex
	byUser map[string][]string
}

func (n *notes) add(ctx context.Context, _ *mcp.CallToolRequest, in noteInput) (*mcp.CallToolResult, noteCount, error) {
	claims, ok := auth.ClaimsFromContext(ctx)
	if !ok {
		return nil, noteCount{}, errNoClaims
	}
	// Both checks are needed. The scope says what the user let this client do on their behalf; it
	// gives the user no rights. The list says what the user may do, with any client.
	if !claims.HasScopes(scopeWrite) {
		return nil, noteCount{}, errors.New("the token does not carry the scope " + scopeWrite)
	}
	if !slices.Contains(n.writers, claims.Subject) {
		return nil, noteCount{}, errors.New("this user may not write notes")
	}
	if in.Text == "" || len(in.Text) > maxNoteBytes {
		return nil, noteCount{}, errors.New("a note is 1 to 1000 bytes")
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	own := n.byUser[claims.Subject]
	if len(own) >= maxNotes {
		return nil, noteCount{}, errors.New("no room for more notes")
	}
	n.byUser[claims.Subject] = append(own, in.Text)
	return nil, noteCount{Count: len(own) + 1}, nil
}

// list answers with the caller's own notes and nobody else's.
func (n *notes) list(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, errNoClaims.Error(), http.StatusInternalServerError)
		return
	}
	n.mu.Lock()
	own := append([]string{}, n.byUser[claims.Subject]...)
	n.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(map[string][]string{"notes": own}); err != nil {
		log.Printf("write response: %v", err)
	}
}
