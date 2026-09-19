# dnsserver

A minimal authoritative DNS server written in Go, from scratch: it parses
and builds DNS packets itself (no third-party DNS library), listens over
UDP, and answers `A` record queries for a set of domains configured in
YAML or JSON.

## Features

- Custom DNS wire-format parser/encoder (`internal/dns`) implementing the
  subset of [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) needed here:
  header, question section, resource records, and name compression.
- UDP server (`internal/server`) that resolves `A` queries against a static,
  configured record set, with per-query structured logging.
- Configuration via YAML or JSON (`internal/config`), selected by the file
  extension (`.json` vs anything else).
- Graceful shutdown on `SIGINT`/`SIGTERM`: the server stops accepting new
  packets and waits for in-flight ones to finish before exiting.
- Unit tests for packet parsing/encoding and config loading, plus
  integration tests that run a real UDP server and query it end to end.

## Behavior

- A query for a configured domain with type `A`/class `IN` gets back the
  configured IP with `NOERROR`.
- A query for a configured domain with any other type/class gets back
  `NOERROR` with zero answers (the name exists, just not that record type).
- A query for an unconfigured domain gets back `NXDOMAIN`.
- Domain matching is case-insensitive and ignores a trailing dot.

## Getting started

```bash
go build -o bin/dnsserver ./cmd/dnsserver
./bin/dnsserver -config config.yaml
```

By default the server listens on `0.0.0.0:8053` (configurable, see below).

Query it with `dig`:

```bash
$ dig @127.0.0.1 -p 8053 example.local

example.local.    60    IN    A    10.0.0.50
```

## Configuration

`config.yaml`:

```yaml
listen: "0.0.0.0:8053"
default_ttl: 60

records:
  - domain: "example.local"
    ip: "10.0.0.50"
  - domain: "test.local"
    ip: "10.0.0.99"
    ttl: 120 # overrides default_ttl for this record
```

The equivalent JSON form (see `config.example.json`) is loaded automatically
when the config file's extension is `.json`:

```bash
./bin/dnsserver -config config.example.json
```

| Field         | Description                                      | Default          |
| ------------- | ------------------------------------------------- | ---------------- |
| `listen`      | UDP address to bind                                | `0.0.0.0:8053`    |
| `default_ttl` | TTL applied to records without their own `ttl`    | `300`             |
| `records`     | List of `{domain, ip, ttl?}` entries               | required, non-empty |

## CLI flags

| Flag          | Description                                  | Default       |
| ------------- | --------------------------------------------- | ------------- |
| `-config`     | Path to the YAML/JSON config file             | `config.yaml` |
| `-log-level`  | `debug`, `info`, `warn`, or `error`           | `info`        |

## Testing

```bash
go test ./...          # unit + integration tests
go test ./... -cover   # with coverage
```

The integration tests in `internal/server` bind a real ephemeral UDP port,
send hand-built DNS queries through the actual `dns` package encoder, and
assert on the parsed response — no mocking of the network stack.

## Project layout

```
cmd/dnsserver/       main entrypoint: flags, logger, config, signal handling
internal/dns/        DNS wire-format parsing and encoding
internal/config/     YAML/JSON configuration loading and validation
internal/server/     UDP server: receive loop, resolution, graceful shutdown
```
