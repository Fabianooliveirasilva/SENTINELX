"""OWASP ZAP (daemon) driven through its API, with network-enforced scope.

Deployment: ZAP runs in its own container whose only network is an internal one
shared with the ZAP scanner worker. It therefore cannot reach anything except the
:class:`EgressGuard` this adapter starts for each scan, which admits only the
authorized origin and connects to the pinned addresses. Redirects or links to
other hosts — including internal ones — are refused hop by hop by the guard.

Per scan the adapter:

1. starts a fresh ZAP session (no data from previous targets);
2. points ZAP's outbound proxy at the guard;
3. creates a context that includes only the authorized URL prefix;
4. runs the traditional spider with depth, children and duration limits;
5. waits for the passive scanner to drain;
6. **only for the ``full`` profile** (requires an *intrusive* authorization) runs
   an active scan restricted to the context, with a duration limit;
7. collects alerts for the target origin, aggregates instances per rule, and
   clears the session.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, ClassVar, Final

import httpx

from sentinelx_security.egress import EgressGuard, EgressPolicy
from sentinelx_security.scanners.base import (
    Evidence,
    Observation,
    RawOutput,
    ScanContext,
    ScanError,
    Scanner,
    ScannerName,
)
from sentinelx_security.scope import AssetType, Technique
from sentinelx_security.scope.targets import parse_target

MAX_ALERTS: Final = 2000
MAX_INSTANCES: Final = 20
RISK_CODES: Final = {"informational": "0", "low": "1", "medium": "2", "high": "3"}
CONFIDENCE_CODES: Final = {
    "false positive": "0",
    "low": "1",
    "medium": "2",
    "high": "3",
    "confirmed": "4",
}
PROFILE_DESCRIPTIONS: Final[Mapping[str, str]] = {
    "baseline": "Spider + passive scan (no attack payloads)",
    "full": "Baseline + active scan (attack payloads; requires an intrusive authorization)",
}


def include_regex(origin: str, path: str) -> str:
    return "^" + re.escape(origin) + re.escape(path or "/") + ".*"


def aggregate_alerts(alerts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Group ZAP alert instances by rule; drop false positives; bound everything."""
    grouped: dict[str, dict[str, Any]] = {}
    for alert in alerts[:MAX_ALERTS]:
        confidence = CONFIDENCE_CODES.get(str(alert.get("confidence", "")).lower(), "1")
        if confidence == "0":
            continue
        plugin = str(alert.get("pluginId") or "0")[:20]
        ref = str(alert.get("alertRef") or plugin)[:40]
        entry = grouped.setdefault(
            ref,
            {
                "plugin_id": plugin,
                "alert_ref": ref,
                "name": str(alert.get("name") or alert.get("alert") or "")[:300],
                "risk_code": RISK_CODES.get(str(alert.get("risk", "")).lower(), "0"),
                "confidence_code": confidence,
                "cwe_id": str(alert.get("cweid") or "")[:10],
                "wasc_id": str(alert.get("wascid") or "")[:10],
                "description": str(alert.get("description") or "")[:4000],
                "solution": str(alert.get("solution") or "")[:4000],
                "reference": str(alert.get("reference") or "")[:4000],
                "instances": [],
                "instance_count": 0,
            },
        )
        entry["instance_count"] += 1
        entry["confidence_code"] = max(entry["confidence_code"], confidence)
        if len(entry["instances"]) < MAX_INSTANCES:
            entry["instances"].append(
                {
                    "url": str(alert.get("url") or "")[:2048],
                    "method": str(alert.get("method") or "")[:10],
                    "param": str(alert.get("param") or "")[:200],
                    "evidence": str(alert.get("evidence") or "")[:500],
                    "attack": str(alert.get("attack") or "")[:500],
                }
            )
    return sorted(grouped.values(), key=lambda a: (-int(a["risk_code"]), a["alert_ref"]))


class ZapScanner(Scanner):
    name: ClassVar[ScannerName] = ScannerName.ZAP
    technique: ClassVar[Technique] = Technique.ACTIVE
    description: ClassVar[str] = (
        "OWASP ZAP baseline (spider + passive rules); active scan only with an intrusive "
        "authorization."
    )
    profiles: ClassVar[Mapping[str, str]] = PROFILE_DESCRIPTIONS
    default_profile: ClassVar[str] = "baseline"
    profile_techniques: ClassVar[Mapping[str, Technique]] = {"full": Technique.INTRUSIVE}
    supported_asset_types = frozenset(
        {
            AssetType.DOMAIN,
            AssetType.SUBDOMAIN,
            AssetType.IP_ADDRESS,
            AssetType.WEB_APPLICATION,
            AssetType.API_ENDPOINT,
        }
    )

    def __init__(
        self,
        *,
        api_url: str = "http://zap:8080",
        api_key: str = "",
        proxy_bind: str = "0.0.0.0",  # noqa: S104  # nosec B104 - internal ZAP network
        proxy_port: int = 8899,
        proxy_advertised_host: str = "scanner-zap",
        transport: httpx.AsyncBaseTransport | None = None,
        poll_interval: float = 2.0,
    ) -> None:
        self._api_url = api_url
        self._api_key = api_key
        self._proxy_bind = proxy_bind
        self._proxy_port = proxy_port
        self._proxy_host = proxy_advertised_host
        self._transport = transport
        self._poll = poll_interval

    @classmethod
    def target_for(cls, asset_type: AssetType, value: str) -> str:
        super().target_for(asset_type, value)
        target = parse_target(value)
        return value if target.is_url else f"https://{target.host_for_netloc}/"

    async def _call(self, client: httpx.AsyncClient, path: str, **params: str) -> dict[str, Any]:
        try:
            response = await client.get(f"/JSON/{path}/", params=params)
        except httpx.HTTPError as exc:
            raise ScanError(
                "zap_unavailable", "The ZAP engine is unreachable.", retryable=True
            ) from exc
        if response.status_code != httpx.codes.OK:
            raise ScanError("zap_error", f"The ZAP engine rejected a request ({path}).")
        data = response.json()
        if not isinstance(data, dict):
            raise ScanError("zap_error", "The ZAP engine returned malformed data.")
        return data

    async def _wait(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict[str, str],
        done: Any,
        deadline: float,
    ) -> bool:
        while time.monotonic() < deadline:
            if done(await self._call(client, path, **params)):
                return True
            await asyncio.sleep(self._poll)
        return False

    async def execute(self, ctx: ScanContext) -> RawOutput:
        if not self._api_key:
            raise ScanError("zap_unavailable", "The ZAP engine is not configured.")
        if not ctx.target.is_url:
            raise ScanError("unsupported_target", "ZAP needs a URL target.")
        if not ctx.pinned_addresses:
            raise ScanError("no_addresses", "No authorized addresses to connect to.")
        url = f"{ctx.target.origin}{ctx.target.path or '/'}"
        start = time.monotonic()
        budget = ctx.timeout_seconds
        guard = EgressGuard(EgressPolicy.for_target(ctx.target, ctx.pinned_addresses))
        async with (
            guard,
            httpx.AsyncClient(
                base_url=self._api_url,
                transport=self._transport,
                headers={"X-ZAP-API-Key": self._api_key},
                timeout=30,
                trust_env=False,
            ) as client,
        ):
            _, port = await guard.start(self._proxy_bind, self._proxy_port)
            version = str((await self._call(client, "core/view/version")).get("version", ""))
            await self._call(client, "core/action/newSession", overwrite="true")
            try:
                await self._call(
                    client,
                    "network/action/setHttpProxy",
                    host=self._proxy_host,
                    port=str(port),
                )
                await self._call(client, "network/action/setHttpProxyEnabled", enabled="true")
                context = f"sentinelx-{uuid.uuid4().hex[:12]}"
                context_id = str(
                    (await self._call(client, "context/action/newContext", contextName=context))[
                        "contextId"
                    ]
                )
                await self._call(
                    client,
                    "context/action/includeInContext",
                    contextName=context,
                    regex=include_regex(ctx.target.origin, ctx.target.path or "/"),
                )
                minutes = str(max(1, int(budget * 0.4 // 60)))
                for option, value in (
                    ("setOptionMaxDuration", minutes),
                    ("setOptionMaxDepth", "5"),
                    ("setOptionMaxChildren", "50"),
                    ("setOptionThreadCount", "2"),
                ):
                    await self._call(client, f"spider/action/{option}", Integer=value)
                spider = await self._call(
                    client,
                    "spider/action/scan",
                    url=url,
                    contextName=context,
                    recurse="true",
                    subtreeOnly="true",
                )
                spider_id = str(spider.get("scan", ""))
                spider_done = await self._wait(
                    client,
                    "spider/view/status",
                    {"scanId": spider_id},
                    lambda d: str(d.get("status")) == "100",
                    start + budget * 0.45,
                )
                if not spider_done:
                    await self._call(client, "spider/action/stop", scanId=spider_id)
                passive_done = await self._wait(
                    client,
                    "pscan/view/recordsToScan",
                    {},
                    lambda d: str(d.get("recordsToScan")) == "0",
                    start + budget * (0.6 if ctx.profile == "full" else 0.9),
                )
                active_done: bool | None = None
                if ctx.profile == "full":
                    await self._call(
                        client,
                        "ascan/action/setOptionMaxScanDurationInMins",
                        Integer=str(max(1, int(budget * 0.3 // 60))),
                    )
                    await self._call(client, "ascan/action/setOptionThreadPerHost", Integer="2")
                    active = await self._call(
                        client,
                        "ascan/action/scan",
                        url=url,
                        recurse="true",
                        inScopeOnly="true",
                        contextId=context_id,
                    )
                    active_id = str(active.get("scan", ""))
                    active_done = await self._wait(
                        client,
                        "ascan/view/status",
                        {"scanId": active_id},
                        lambda d: str(d.get("status")) == "100",
                        start + budget * 0.92,
                    )
                    if not active_done:
                        await self._call(client, "ascan/action/stop", scanId=active_id)
                alerts = (
                    await self._call(
                        client,
                        "alert/view/alerts",
                        baseurl=ctx.target.origin,
                        start="0",
                        count=str(MAX_ALERTS),
                    )
                ).get("alerts", [])
                urls = (await self._call(client, "core/view/urls", baseurl=ctx.target.origin)).get(
                    "urls", []
                )
            finally:
                with contextlib.suppress(ScanError):
                    await self._call(client, "core/action/newSession", overwrite="true")
        return RawOutput(
            data={
                "url": url,
                "profile": ctx.profile,
                "alerts": aggregate_alerts([a for a in alerts if isinstance(a, dict)]),
                "urls_discovered": len(urls) if isinstance(urls, list) else 0,
                "spider_completed": spider_done,
                "passive_completed": passive_done,
                "active_completed": active_done,
                "egress": guard.stats.summary(),
            },
            tool_versions={"zap": version[:40]},
        )

    def normalize_results(self, raw: RawOutput) -> list[Observation]:
        origin = parse_target(raw.data["url"]).origin
        return [
            Observation(kind="web_alert", key=f"{alert['alert_ref']} {origin}", data=alert)
            for alert in raw.data["alerts"]
        ]

    def record_evidence(self, raw: RawOutput) -> list[Evidence]:
        data = raw.data
        egress = data["egress"]
        lines = [
            f"target: {data['url']}",
            f"profile: {data['profile']}",
            f"urls discovered: {data['urls_discovered']}",
            f"spider completed: {data['spider_completed']}",
            f"passive scan completed: {data['passive_completed']}",
            f"active scan completed: {data['active_completed']}",
            f"egress connections: {egress['connections']}, denied: {egress['denied_total']}",
        ]
        lines += [f"denied destination: {d}" for d in egress["denied_destinations"]]
        lines += [
            f"alert {a['alert_ref']} risk={a['risk_code']} x{a['instance_count']}: {a['name']}"
            for a in data["alerts"]
        ]
        return [Evidence.bounded("ZAP run summary", "\n".join(lines))]
