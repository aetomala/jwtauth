# Contributing

Contributions welcome. This library follows strict quality standards — please review the requirements and workflow below before opening a PR.

## Requirements

- All code must have tests
- Tests must pass with race detector (`-race` flag)
- Coverage >80% for critical paths
- Integration tests for complex flows
- Examples for new features
- Follow existing architecture patterns — see [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md)
- Use Ginkgo/Gomega for BDD-style tests
- Update documentation for new features

## Development Workflow

```bash
# Clone and setup
git clone https://github.com/aetomala/jwtauth.git
cd jwtauth

# Run the full CI suite locally (vet, golangci-lint, govulncheck, build, unit + integration tests)
./run-ci-locally.sh

# Or run tests directly
ginkgo -r --race ./...
```

## Branching and PR Workflow

- Branch off `dev` using the format `<area>/short-description`
- PRs target `dev`, never `main`
- One logical concern per PR — avoid bundling unrelated changes

## Code Standards

- Follow the architecture patterns described in [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md)
- Add observability (logging, metrics, tracing) for any new component — see the Adding Observability section in ARCHITECTURE.md for the required pattern
- Apply the GoDoc documentation style used throughout the existing codebase
- No nil guards at observability call sites — assign no-op implementations at construction time instead
