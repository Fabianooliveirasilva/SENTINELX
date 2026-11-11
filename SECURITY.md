# Security Policy

## Supported versions

SentinelX is pre-1.0. Security fixes are applied to the `main` branch.

## Reporting a vulnerability

**Please do not open public issues for security vulnerabilities.**

Use GitHub's private vulnerability reporting ("Report a vulnerability" under the
repository's **Security** tab). Include:

* affected component and version/commit,
* reproduction steps or proof of concept,
* impact assessment,
* any suggested remediation.

You can expect an acknowledgement within 5 business days and a status update
within 14 days. Coordinated disclosure is appreciated; reporters are credited
unless they prefer otherwise.

## Scope

In scope: the SentinelX application code, container images and CI configuration
in this repository.

Out of scope: findings produced by SentinelX about third-party systems, issues
that require a compromised host or administrator account, and denial of service
against development deployments.

## Responsible use

SentinelX must only be used against assets you own or are explicitly authorized
to assess. See the [scanning policy](docs/SCANNING_POLICY.md) and
[security controls](docs/SECURITY.md).
