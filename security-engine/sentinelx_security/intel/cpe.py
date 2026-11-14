"""CPE 2.3 parsing and version-range matching.

NVD expresses affected software as CPE match criteria, optionally bounded by
``versionStart/End Including/Excluding``. A component is affected only when
vendor and product are equal and its version falls inside the range. A
component without a version never matches: SentinelX never asserts a CVE from a
product name alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cmp_to_key
from typing import Final

ANY: Final = "*"
NOT_APPLICABLE: Final = "-"
_TOKEN = re.compile(r"\d+|[a-z]+")
PRE_RELEASE: Final = frozenset({"alpha", "beta", "rc", "pre", "preview", "dev", "snapshot"})


class CpeError(ValueError):
    pass


def _split_escaped(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


@dataclass(frozen=True, slots=True)
class Cpe:
    part: str
    vendor: str
    product: str
    version: str
    update: str

    @classmethod
    def parse(cls, value: str) -> Cpe:
        fields = _split_escaped(value.strip())
        if len(fields) != 13 or fields[0] != "cpe" or fields[1] != "2.3":
            raise CpeError(f"not a CPE 2.3 formatted string: {value[:80]!r}")
        part, vendor, product, version, update = (f.lower() for f in fields[2:7])
        if part not in {"a", "o", "h", ANY} or not vendor or not product:
            raise CpeError(f"invalid CPE components: {value[:80]!r}")
        return cls(part, vendor, product, version or ANY, update or ANY)


def _tokens(version: str) -> list[str]:
    return _TOKEN.findall(version.lower())


def compare_versions(left: str, right: str) -> int:
    """Compare dotted versions numerically.

    ``1.10 > 1.9``, ``2.4.49 < 2.4.50``, ``3.5.0 == 3.5``, ``1.0rc1 < 1.0`` and
    ``1.0.2k > 1.0.2`` (pre-release markers sort low, other suffixes high).
    """
    a, b = _tokens(left), _tokens(right)
    for x, y in zip(a, b, strict=False):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return -1 if int(x) < int(y) else 1
        if x.isdigit() != y.isdigit():
            # "1.0rc1" < "1.0.1"; ambiguous cases ("1.0.2k" vs "1.0.2.1") favour digits.
            return 1 if x.isdigit() else -1
        return -1 if x < y else 1
    if len(a) == len(b):
        return 0
    longer, sign = (a, 1) if len(a) > len(b) else (b, -1)
    rest = longer[min(len(a), len(b)) :]
    if all(t.isdigit() and int(t) == 0 for t in rest):
        return 0
    # "1.0" vs "1.0rc1": a pre-release marker sorts lower; any other suffix is a
    # later patch level (OpenSSL "1.0.2k" > "1.0.2", OpenSSH "8.9p1" > "8.9").
    return -sign if rest[0] in PRE_RELEASE else sign


version_key = cmp_to_key(compare_versions)


@dataclass(frozen=True, slots=True)
class CpeRange:
    criteria: str
    vendor: str
    product: str
    version: str
    update: str
    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None

    @classmethod
    def from_criteria(
        cls,
        criteria: str,
        *,
        start_including: str | None = None,
        start_excluding: str | None = None,
        end_including: str | None = None,
        end_excluding: str | None = None,
    ) -> CpeRange:
        cpe = Cpe.parse(criteria)
        return cls(
            criteria=criteria,
            vendor=cpe.vendor,
            product=cpe.product,
            version=cpe.version,
            update=cpe.update,
            start_including=start_including,
            start_excluding=start_excluding,
            end_including=end_including,
            end_excluding=end_excluding,
        )

    @property
    def bounded(self) -> bool:
        return any(
            (self.start_including, self.start_excluding, self.end_including, self.end_excluding)
        )

    def describe(self) -> str:
        if self.version not in (ANY, NOT_APPLICABLE):
            return f"version {self.version}" + (
                f" ({self.update})" if self.update not in (ANY, NOT_APPLICABLE) else ""
            )
        bounds = []
        if self.start_including:
            bounds.append(f">= {self.start_including}")
        if self.start_excluding:
            bounds.append(f"> {self.start_excluding}")
        if self.end_including:
            bounds.append(f"<= {self.end_including}")
        if self.end_excluding:
            bounds.append(f"< {self.end_excluding}")
        return " and ".join(bounds) if bounds else "all versions"

    def matches(self, vendor: str, product: str, version: str, update: str = "") -> bool:
        if vendor.lower() != self.vendor or product.lower() != self.product:
            return False
        if not version or self.version == NOT_APPLICABLE:
            return False
        if self.update not in (ANY, NOT_APPLICABLE, "") and update.lower() != self.update:
            return False
        if self.version != ANY:
            return compare_versions(version, self.version) == 0
        if self.start_including and compare_versions(version, self.start_including) < 0:
            return False
        if self.start_excluding and compare_versions(version, self.start_excluding) <= 0:
            return False
        if self.end_including and compare_versions(version, self.end_including) > 0:
            return False
        return not (self.end_excluding and compare_versions(version, self.end_excluding) >= 0)
