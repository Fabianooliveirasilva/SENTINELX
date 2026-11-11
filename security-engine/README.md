# sentinelx-security

Framework-independent security logic used by the API and workers.

| Module | Purpose |
|--------|---------|
| `scope.targets` | Strict parsing/normalization of hostnames, IPs, URLs and `host:port` targets |
| `scope.network_policy` | Deny-by-default network policy (blocks loopback, private, link-local, metadata, embedded IPv4 in IPv6…) |
| `scope.resolver` | DNS resolution (A/AAAA) with timeouts; deterministic static resolver for tests |
| `scope.engine` | Scope decisions: asset match → authorization → technique → per-address verdicts, plus redirect validation |

See [docs/SCANNING_POLICY.md](../docs/SCANNING_POLICY.md) for the normative rules.
