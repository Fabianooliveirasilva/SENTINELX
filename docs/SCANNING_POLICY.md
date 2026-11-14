# SentinelX Scanning Policy

> This policy is normative. **Implemented:** asset registration rules,
> authorization records, the deny-by-default network policy and the scope engine
> (Phase 3); scan orchestration, the scanner sandbox and the reconnaissance
> scanners — DNS, certificate transparency, TLS, HTTP fingerprinting and Nmap
> (Phase 4); OWASP ZAP, Nuclei, the egress guard and findings (Phase 5).

## 1. Principles

1. **Deny by default.** Nothing is scanned unless every rule below is satisfied.
2. **Explicit authorization.** Active testing requires a recorded authorization
   from the asset owner, with scope, validity window and reference.
3. **Least intrusive first.** Passive techniques are preferred; active techniques
   are opt-in per asset and per authorization.
4. **Verifiable scope.** Every target IP and URL is validated at execution time,
   not only at registration time.
5. **Evidence and provenance.** Every result records the tool, version, profile,
   template identifiers, timestamps and the job's correlation ID.

## 2. Preconditions for any active scan

* The asset belongs to the caller's project, is `active` and `scan_eligible`.
* An `asset_authorization` exists that is active now (`valid_from ≤ now ≤ valid_until`)
  and explicitly allows the requested technique class.
* The caller holds `scans:execute` in that project.
* Every resolved address is inside the authorized scope **and** is not in a
  blocked range (below). Domain authorization does **not** imply authorization
  for every IP the domain resolves to (e.g. shared CDN or hosting addresses).
* Project quotas (concurrent jobs, daily jobs) are not exceeded.

## 2a. How a scope decision is made

1. Parse and normalize the target (hostname, IP, `host:port` or http(s) URL).
2. Literal IPs refused by the network policy are denied immediately, with the
   precise reason (also for passive checks).
3. Special-use names (`.local`, `.internal`, `.test`, …) are denied unless they are
   inside a configured lab domain.
4. A registered **active** asset must cover the target: exact host, IP, origin +
   path prefix for web apps/APIs, host + port for services. Subdomains are covered
   only when the authorization sets `include_subdomains`.
5. An authorization must be **current** (not revoked, inside its window) and permit
   the technique (passive / active / intrusive).
6. Passive techniques stop here. Active and intrusive techniques resolve the host
   once; **every** resolved address must pass the network policy **and** be
   explicitly authorized (inside the authorization's IP ranges or registered as an
   authorized IP asset). The resolved set is returned as the pinned address list
   scanners must use (DNS-rebinding defense).
7. HTTP redirects are validated hop by hop with the same procedure.

Authorization constraints: window ≤ `SENTINELX_MAX_AUTHORIZATION_DAYS` (366),
IP ranges no broader than /16 (IPv4) or /48 (IPv6) and publicly routable (or in a
lab), intrusive testing only by administrators and only together with active
testing (also enforced by a database constraint).

## 3. Always-blocked destinations

Loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0/8`, `::`), link-local
(`169.254.0.0/16`, `fe80::/10`, including cloud metadata endpoints), private
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), CGNAT
(`100.64.0.0/10`), multicast and reserved ranges, IPv4-mapped/translated IPv6
forms of any of the above, and SentinelX's own infrastructure.

Private ranges may be enabled **only** for explicitly configured lab networks by
an administrator (`SENTINELX_SCOPE_LAB_NETWORKS`, `SENTINELX_SCOPE_LAB_DOMAINS`),
and never for the platform's own networks. Lab networks cannot overlap loopback,
link-local (metadata), multicast, unspecified or reserved space.

Ambiguous inputs are rejected before any lookup: numeric host forms that resolvers
turn into IPs (`2130706433`, `0x7f.1`, `0177.0.0.1`), IPv6 zone IDs, credentials
in URLs, wildcards and non-http(s) schemes. IDN names are compared in punycode.

## 4. Technique classes

| Class | Examples | Default |
|-------|----------|---------|
| Passive | DNS records, certificate transparency, public passive sources | Allowed on authorized assets |
| Low-impact active | TCP connect scan on a bounded port list, service/version detection, TLS handshake analysis, HTTP header checks | Requires authorization flag `active_scanning_allowed` |
| Application DAST | OWASP ZAP baseline (passive rules) | Requires authorization flag |
| Intrusive DAST | ZAP active scan | Requires a separate explicit flag, time window and Admin approval |

## 5. Prohibited, always

Exploitation, brute force or credential attacks, denial-of-service or load
testing, fuzzing for crash discovery, stealth/evasion/decoy/fragmentation options,
intrusive or `exploit`/`brute`/`dos`/`fuzz`/`intrusive` Nmap NSE categories and
equivalent Nuclei tags, user-supplied command-line flags, and scanning of
third-party infrastructure discovered during reconnaissance unless it is
separately registered and authorized.

## 6. Tool-specific rules

* **Nmap:** server-defined profiles only (`quick`, `standard`, `web`); TCP
  connect scans (`-sT`) as an unprivileged user; bounded port sets; `--max-rate`,
  `--max-retries`, `--host-timeout` and an overall timeout enforced; no NSE script
  selection (only `-sV --version-light` probes); forbidden options (`--script`,
  `-A`, `-O`, `-sS`, `-sU`, decoys, spoofing, fragmentation) are rejected by a test.
* **HTTP fingerprinting:** one `GET` per pinned address, sent to the IP with the
  original `Host` header and SNI; redirects are recorded, never followed; bodies
  read up to 256 KiB and matched only against fixed patterns.
* **Passive sources:** certificate transparency (crt.sh) is queried for the
  authorized domain only; discovered names are reported with provenance and are
  never scanned until registered and authorized. Can be disabled with
  `SENTINELX_PASSIVE_SOURCES_ENABLED=false`.
* **Egress guard (ZAP, Nuclei).** These tools resolve names themselves, so they
  never get direct network access to targets. Each scan starts a forward proxy
  (`sentinelx_security.egress`) that accepts only `CONNECT` tunnels and
  absolute-form HTTP requests whose `host:port` equals the authorized target,
  connects to the **pinned addresses** (it never resolves DNS), enforces a
  connection/byte budget and idle timeout, and records every denied destination
  in the scan evidence. Redirects and links to any other host — including
  internal and metadata addresses — are therefore refused hop by hop.
* **OWASP ZAP:** runs as a daemon in the `zap` container, whose **only** network
  is the internal `zap-net`; its sole way out is the guard in `scanner-zap`.
  Profile `baseline` (default, technique *active*) = traditional spider (depth 5,
  50 children, duration-limited, subtree only) + passive rules. Profile `full`
  adds an active scan restricted to the context and is classified **intrusive**:
  it requires an authorization with `allow_intrusive`, which only administrators
  can record. Each scan uses a fresh ZAP session that is cleared afterwards;
  scans are serialized on the `scans.zap` queue.
* **Nuclei:** version-pinned binary and template release (both SHA-256 verified
  at image build); only allowlisted template directories (`http/misconfiguration`,
  `http/exposures/…`, `http/technologies`, `http/exposed-panels`), only the
  `http` protocol, excluded tags (`intrusive`, `dos`, `fuzz`, `brute-force`,
  `default-login`, `rce`, `sqli`, `xss`, `lfi`, `ssrf`, `oast`, `exploit`,
  `takeover`, …), interactsh disabled, update checks disabled, rate limit 20 rps,
  concurrency 5, no retries; template IDs and versions recorded. Nuclei shares the
  scanner container's network, so the guard is enforced by configuration
  (`-proxy`) rather than by network isolation as for ZAP.
* **Tool environment:** scanner subprocesses receive only `PATH`, `HOME=/tmp` and
  a locale — never the worker's broker credentials.

## 7. Execution controls

Implemented in Phase 4:

* **Two scope checks.** The API runs a static preflight (asset active, current
  authorization permits the scanner's technique, scanner supports the asset
  type). The authoritative check runs again *inside the sandbox* immediately
  before execution, against a fresh snapshot of the project's authorizations and
  fresh DNS. Scanners connect only to the addresses pinned by that decision; a
  revoked authorization or a rebinding answer between request and execution
  denies the job (`scope_denied`, audited as `scan.scope_denied`).
* **Sandbox.** The `scanner` service consumes only the `scans` queue. It runs as
  a non-root user with no Linux capabilities, a read-only root filesystem, CPU,
  memory and PID limits, and **no database URL or signing secret**. The worker
  process is recycled after every scan. It is the only container attached to the
  `scan-egress` network.
* **Server-side profiles only.** The request carries a scanner name and a profile
  name validated against an allowlist; no flags, ports or scripts can be supplied.
* **Time and size limits.** Per-scan timeout (`SENTINELX_SCAN_TIMEOUT_SECONDS`),
  Celery soft/hard limits, per-tool timeouts with process-group kill, response and
  evidence size caps, observation count caps.
* **Quotas.** `SENTINELX_MAX_CONCURRENT_SCANS_PER_PROJECT` and
  `SENTINELX_MAX_DAILY_SCANS_PER_PROJECT`, enforced under a per-project row lock.
* **Cancellation and emergency stop.** Analysts can cancel their project's jobs;
  administrators can trigger a **platform-wide emergency stop** that cancels every
  pending, queued and running job (terminating the sandbox task) and blocks new
  scans until scanning is explicitly resumed. Both are audited.
* **Lost work.** Jobs whose messages were lost are failed by a periodic expiry
  task, so a broker outage never leaves jobs "running" forever.

Not yet enforced at the network layer: an egress firewall that only permits the
pinned addresses (the scope engine enforces this in-process). See
[DEPLOYMENT.md](DEPLOYMENT.md) for the recommended production control.

## 8. Findings and reporting rules

Findings are derived deterministically from observations by a versioned rule set
(`sentinelx_security/findings.py`, `RULESET_VERSION`). Third-party verdicts keep
their own scales: ZAP risk/confidence are mapped, never upgraded, and alerts ZAP
marks as false positives are dropped; Nuclei matches are `firm`, not
`confirmed` (a signature match is not proof of exploitability). A finding is
`confirmed` only when the observation itself is the proof (e.g. an expired
certificate presented by the server). Analyst decisions (`false_positive`,
`accepted_risk`) require a reason and are never overridden by later scans.

CVE findings (Phase 6) come only from a versioned component whose CPE mapping
and version fall inside an NVD *vulnerable* range; a product name without a
version never produces a CVE finding. They are always `tentative`, carry the
matched criterion and range as evidence, and resolve automatically when a later
scan reports a version outside the range.

Reports state methodology, scope, authorization reference, tool
versions and limitations, and clearly label AI-generated commentary.
