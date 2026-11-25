# Sample MCP server

An MCP server whose users sign in with Passflow. It uses [`auth.ProtectedResource`](../../README.md#protect-an-mcp-server) to verify access tokens and the official [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk) for the protocol.

## Register the resource

In the Passflow server config, name the URL of the MCP server and its scopes. Use the same URL in `MCP_RESOURCE`.

```yaml
oidc:
  resources:
    - uri: http://localhost:8090/mcp
      name: Sample notes
      scopes: [mcp, "notes:write"]
```

## Run

From this directory:

```sh
PASSFLOW_ISSUER=http://localhost:8765 MCP_RESOURCE=http://localhost:8090/mcp go run .
```

Then add `http://localhost:8090/mcp` to an MCP client and call `whoami`.

| Variable | Default | Meaning |
|---|---|---|
| `PASSFLOW_ISSUER` | required | The issuer tokens must name, exactly as Passflow writes it |
| `MCP_RESOURCE` | required | The public URL of this server, with the path `/mcp`. Tokens must carry it as their audience |
| `MCP_WRITERS` | empty | Comma-separated user IDs that may write notes. Empty means nobody |
| `MCP_ADDR` | `localhost:8090` | The address to listen on |

The issuer and the resource must use `https`, except on a loopback host.

## Who may do what

| Request | Scopes of the token | Other check |
|---|---|---|
| `whoami` tool | `mcp` | none |
| `add_note` tool | `mcp`, `notes:write` | the user is in `MCP_WRITERS` |
| `GET /notes` | `mcp`, `notes:write` | answers with the caller's own notes |
| `/.well-known/oauth-protected-resource/mcp` and the same path without `/mcp` | no token | none |

A scope is what the user let a client do. It gives the user no rights, so `add_note` also checks the user. Replace `MCP_WRITERS` with your own permissions.

The server's challenge asks for `mcp` only. `GET /notes` answers 403 and names both scopes when the token lacks `notes:write`. A tool call answers inside the MCP response instead, so `add_note` returns a tool error, and the client must be set to ask for `notes:write`.

The server reads the token's claims and makes no UserInfo request. Notes stay in memory, at most 100 for each user, and a restart deletes them.

## Docker

From the directory of the `passflow-go` module, two levels up:

```sh
docker build -f examples/mcp-server/Dockerfile -t passflow-sample-mcp .
docker run --rm -p 8090:8090 \
  -e PASSFLOW_ISSUER=https://auth.example.com \
  -e MCP_RESOURCE=https://mcp.example.com/mcp \
  passflow-sample-mcp
```

Put a proxy with TLS in front of the container. A proxy that reaches the server through a loopback address must send a loopback `Host` header, because the MCP SDK refuses any other one there.

`/mcp` sends no CORS headers. Add them if a client runs in a browser on another origin.
