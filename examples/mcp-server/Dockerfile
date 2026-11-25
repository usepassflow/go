# Build from the directory of the passflow-go module:
#   docker build -f examples/mcp-server/Dockerfile -t passflow-sample-mcp .
FROM golang:1.27.4-alpine3.23 AS builder
WORKDIR /module
COPY . .
WORKDIR /module/examples/mcp-server
RUN CGO_ENABLED=0 go build -trimpath -o /mcp-server .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /mcp-server /mcp-server
ENV MCP_ADDR=:8090
EXPOSE 8090
ENTRYPOINT ["/mcp-server"]
