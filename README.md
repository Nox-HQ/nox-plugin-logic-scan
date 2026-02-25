# nox-plugin-logic-scan

A Nox plugin for business logic security analysis and control flow validation.

## Features

- Application logic security analysis
- Business logic vulnerability detection
- Control flow validation
- Workflow integrity checking

## Installation

```bash
go install github.com/nox-hq/nox-plugin-logic-scan@latest
```

## Usage

```bash
nox scan . --plugin nox-plugin-logic-scan
```

## Configuration

Configure the plugin via `nox.yaml`:

```yaml
plugins:
  - name: nox-plugin-logic-scan
    config:
      # Plugin-specific configuration
```

## Development

```bash
# Build
make build

# Test
make test

# Lint
make lint
```

## License

Apache License 2.0
