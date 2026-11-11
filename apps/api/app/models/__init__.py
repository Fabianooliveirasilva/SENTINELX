"""ORM models. Importing this package registers every table on ``Base.metadata``."""

from app.models.asset import Asset, AssetAuthorization
from app.models.audit import AuditLog
from app.models.finding import Finding, FindingOccurrence, FindingStatusChange
from app.models.identity import PasswordResetToken, Permission, RefreshToken, Role, User
from app.models.platform import PlatformSetting
from app.models.project import Project, ProjectMember
from app.models.scan import ScanEvidence, ScanJob, ScanResult

__all__ = [
    "Asset",
    "AssetAuthorization",
    "AuditLog",
    "Finding",
    "FindingOccurrence",
    "FindingStatusChange",
    "PasswordResetToken",
    "Permission",
    "PlatformSetting",
    "Project",
    "ProjectMember",
    "RefreshToken",
    "Role",
    "ScanEvidence",
    "ScanJob",
    "ScanResult",
    "User",
]
