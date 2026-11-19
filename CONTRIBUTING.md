# Contributing

Thanks for helping improve AgentGuard.

## Development requirements

- Go 1.22+
- Git

## Checks

```bash
gofmt -w .
go vet ./...
go test -race ./...
```

## Pull requests

Keep changes focused, add tests for behavior changes, document security implications, and avoid introducing network access or destructive behavior into the scanner. New integrations should default to least-privilege read-only access.
