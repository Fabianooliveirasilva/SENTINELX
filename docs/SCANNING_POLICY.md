# SentinelX Scanning Policy

> This policy is normative. **Implemented (Phase 3):** asset registration rules,
> authorization records, the deny-by-default network policy and the scope engine
> (`security-engine/sentinelx_security/scope`). Scanner execution controls arrive
> in Phases 4–5; until then SentinelX performs **no** network scanning.

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

* **Nmap:** server-defined profiles only; TCP connect scans; bounded port sets;
  `--max-rate`, `--host-timeout` and overall timeouts enforced; NSE limited to
  an allowlist of `safe`/`default`/`version` scripts.
* **OWASP ZAP:** baseline (passive) by default; context restricted to the
  authorized URLs; maximum duration; redirects outside scope not followed.
* **Nuclei:** curated, reviewed, version-pinned template set; tags restricted
  (no `intrusive`, `dos`, `fuzz`, `brute-force`, `exploit` or credential
  templates); protocols restricted; rate limited; template IDs recorded.

## 7. Execution controls

Isolated, short-lived, non-root sandbox containers; CPU/memory/time limits; no
access to application secrets or internal networks; egress limited to the
validated target set; output size limits; operator **emergency stop** that
cancels all running jobs of a project.

## 8. Reporting rules

A finding is `confirmed` only with sufficient evidence; scanner hypotheses are
marked as such. Reports state methodology, scope, authorization reference, tool
versions and limitations, and clearly label AI-generated commentary.
