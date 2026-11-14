"""ORM models. Importing this package registers every table on ``Base.metadata``."""

from app.models.ai import AIAnalysis
from app.models.asset import Asset, AssetAuthorization
from app.models.audit import AuditLog
from app.models.finding import (
    Finding,
    FindingOccurrence,
    FindingRiskChange,
    FindingStatusChange,
    ProjectRiskSnapshot,
)
from app.models.identity import PasswordResetToken, Permission, RefreshToken, Role, User
from app.models.intel import Cve, CveMatch, IntelSource, ProductSync, SoftwareComponent
from app.models.monitoring import (
    AlertRule,
    Notification,
    NotificationChannel,
    ScanSchedule,
    SecurityEvent,
    alert_rule_channels,
)
from app.models.platform import PlatformSetting
from app.models.project import Project, ProjectMember
from app.models.scan import ScanEvidence, ScanJob, ScanResult

__all__ = [
    "AIAnalysis",
    "AlertRule",
    "Asset",
    "AssetAuthorization",
    "AuditLog",
    "Cve",
    "CveMatch",
    "Finding",
    "FindingOccurrence",
    "FindingRiskChange",
    "FindingStatusChange",
    "IntelSource",
    "Notification",
    "NotificationChannel",
    "PasswordResetToken",
    "Permission",
    "PlatformSetting",
    "ProductSync",
    "Project",
    "ProjectMember",
    "ProjectRiskSnapshot",
    "RefreshToken",
    "Role",
    "ScanEvidence",
    "ScanJob",
    "ScanResult",
    "ScanSchedule",
    "SecurityEvent",
    "SoftwareComponent",
    "User",
    "alert_rule_channels",
]
