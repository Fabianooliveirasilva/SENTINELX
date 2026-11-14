"""Role-based access control catalog.

This module is the single source of truth for roles and permissions. The
database tables ``roles``, ``permissions`` and ``role_permissions`` are seeded
from it by migrations, and an integration test asserts they stay in sync.

Authorization is always enforced server-side from these permissions; the
frontend only uses them to hide controls the user cannot use.
"""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType


class RoleName(StrEnum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    VIEWER = "viewer"


class Permission(StrEnum):
    # Platform administration (Phase 2)
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"
    ROLES_READ = "roles:read"
    PROJECTS_READ = "projects:read"
    PROJECTS_MANAGE = "projects:manage"
    AUDIT_READ = "audit:read"
    SETTINGS_MANAGE = "settings:manage"
    # Security operations (enforced by the phases that introduce each module)
    ASSETS_READ = "assets:read"
    ASSETS_WRITE = "assets:write"
    SCANS_READ = "scans:read"
    SCANS_EXECUTE = "scans:execute"
    FINDINGS_READ = "findings:read"
    FINDINGS_WRITE = "findings:write"
    INTELLIGENCE_READ = "intelligence:read"
    EVENTS_READ = "events:read"
    ALERTS_MANAGE = "alerts:manage"
    REPORTS_READ = "reports:read"
    REPORTS_GENERATE = "reports:generate"
    AI_USE = "ai:use"


PERMISSION_DESCRIPTIONS: MappingProxyType[Permission, str] = MappingProxyType(
    {
        Permission.USERS_READ: "View user accounts",
        Permission.USERS_MANAGE: "Create, update, deactivate users and revoke their sessions",
        Permission.ROLES_READ: "View roles and their permissions",
        Permission.PROJECTS_READ: "View projects the user is a member of",
        Permission.PROJECTS_MANAGE: "Create, update and delete projects and manage members",
        Permission.AUDIT_READ: "View the security audit log",
        Permission.SETTINGS_MANAGE: "Manage platform settings",
        Permission.ASSETS_READ: "View assets",
        Permission.ASSETS_WRITE: "Register and modify assets and authorizations",
        Permission.SCANS_READ: "View scans and results",
        Permission.SCANS_EXECUTE: "Launch and cancel scans on authorized assets",
        Permission.FINDINGS_READ: "View findings and evidence",
        Permission.FINDINGS_WRITE: "Triage findings and change their lifecycle status",
        Permission.INTELLIGENCE_READ: "Query threat intelligence",
        Permission.EVENTS_READ: "View security events",
        Permission.ALERTS_MANAGE: "Manage alert rules and notification channels",
        Permission.REPORTS_READ: "View and download reports",
        Permission.REPORTS_GENERATE: "Generate reports",
        Permission.AI_USE: "Request AI-assisted analysis",
    }
)

ROLE_DESCRIPTIONS: MappingProxyType[RoleName, str] = MappingProxyType(
    {
        RoleName.ADMIN: "Full administrative permissions across the platform.",
        RoleName.SECURITY_ANALYST: (
            "Manage authorized assets, execute scans, investigate findings and generate reports "
            "in assigned projects."
        ),
        RoleName.VIEWER: "Read-only access to assigned projects and reports.",
    }
)

_VIEWER = frozenset(
    {
        Permission.PROJECTS_READ,
        Permission.ASSETS_READ,
        Permission.SCANS_READ,
        Permission.FINDINGS_READ,
        Permission.INTELLIGENCE_READ,
        Permission.EVENTS_READ,
        Permission.REPORTS_READ,
    }
)

_ANALYST = _VIEWER | {
    Permission.ASSETS_WRITE,
    Permission.SCANS_EXECUTE,
    Permission.FINDINGS_WRITE,
    Permission.ALERTS_MANAGE,
    Permission.REPORTS_GENERATE,
    Permission.AI_USE,
}

ROLE_PERMISSIONS: MappingProxyType[RoleName, frozenset[Permission]] = MappingProxyType(
    {
        RoleName.ADMIN: frozenset(Permission),
        RoleName.SECURITY_ANALYST: frozenset(_ANALYST),
        RoleName.VIEWER: _VIEWER,
    }
)
