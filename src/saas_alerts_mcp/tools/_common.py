# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Shared argument types, event shaping and the error-handling wrapper."""

import functools
import inspect
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated, Any

from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import _SHRINK_STEPS, MAX_CHARS, _shrink, dump_json_capped, error_envelope
from .._json import compact as compact_json
from ..api_client import SaasAlertsClient, SaasAlertsError

logger = logging.getLogger("saas_alerts_mcp.tools")

ClientFactory = Callable[[], SaasAlertsClient | None]

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)
LOCAL = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False)
WRITES = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True)
WRITES_IDEMPOTENT = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True)

NOT_CONFIGURED = error_envelope(
    "not_configured", "SaaS Alerts credentials are missing for this request (X-SaaS-Alerts-API-Key).", False
)

CustomerId = Annotated[str, Field(description="SaaS Alerts customer id (from saas_alerts_customers_list).", min_length=1)]
Confirm = Annotated[bool | None, Field(description="Must be true to delete; ask the user first.")]
Verbose = Annotated[
    bool | None, Field(description="Return full raw event records (large). Default false: triage fields only.")
]

# Event fields worth showing when triaging; everything else is raw detail.
_TRIAGE_FIELDS = (
    "_id",
    "eventId",
    "time",
    "type",
    "jointType",
    "alertStatus",
    "status",
    "jointDesc",
    "jointDescAdditional",
    "operation",
    "user",
    "userEmail",
    "email",
    "customer",
    "product",
    "appName",
    "ip",
)


def from_alias(function: Callable[..., Awaitable[str]]) -> Callable[..., Awaitable[str]]:
    """Expose a ``from_`` parameter as ``from`` (a Python keyword)."""

    @functools.wraps(function)
    async def wrapper(**kwargs: Any) -> str:
        if "from" in kwargs:
            kwargs["from_"] = kwargs.pop("from")
        return await function(**kwargs)

    wrapper.__signature__ = inspect.signature(function)  # type: ignore[attr-defined]
    return wrapper


def compact(values: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if v is not None}


Offset = Annotated[
    int | None, Field(description="Record position to start from (0-based); pass next_offset from the previous result.", ge=0)
]
Limit = Annotated[int | None, Field(description="Records to return (default: as many as fit the response size limit).", ge=1)]


def local_page(rows: list, key: str, offset: int | None, limit: int | None, **extra: Any) -> dict:
    """Page a list the API returns in full: ``rows[offset:offset+limit]`` plus paging fields.

    next_offset continues right after the last record returned, also when the result is cut to
    fit the size limit (these endpoints take no page size, so nothing else could continue it).
    """
    start = offset or 0
    shown = rows[start:] if limit is None else rows[start : start + limit]
    more = start + len(shown) < len(rows)
    result: dict[str, Any] = {**extra, key: shown, "count": len(shown), "total": len(rows), "offset": start, "has_more": more}
    if more:
        result["next_offset"] = start + len(shown)
    return result | {"_resume": {"key": "next_offset", "start": start}}


def es_capped(payload: dict) -> str:
    """Cap an Elasticsearch response whose records sit in the nested ``hits.hits``.

    The shared size limit only cuts top-level lists. Here long fields are shortened first; if the
    hits still do not fit, the first ones that fit are returned and ``_scroll_id`` is left out,
    since following it would skip the cut hits (a scroll cannot go back).
    """
    text = compact_json(payload)
    if len(text) <= MAX_CHARS:
        return text
    hits = payload.get("hits") if isinstance(payload.get("hits"), dict) else {}
    items = hits.get("hits") if isinstance(hits.get("hits"), list) else []
    shortened = items
    for text_limit, list_limit in _SHRINK_STEPS:
        shortened = [_shrink(h, text_limit, list_limit) for h in items]
        candidate = payload | {"hits": hits | {"hits": shortened}, "fields_truncated": True}
        if len(compact_json(candidate)) <= MAX_CHARS:
            return compact_json(candidate)

    def build(n: int) -> dict:
        rest = {k: v for k, v in payload.items() if k != "_scroll_id"}
        return rest | {
            "hits": hits | {"hits": shortened[:n]},
            "truncated": True,
            "has_more": True,
            "original_count": len(items),
            "note": f"Only {n} of {len(items)} hits fit the response size limit. _scroll_id was left out because "
            "following it would skip the rest; run the search again with a smaller size in the body.",
        }

    lo, hi = 0, len(items)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(compact_json(build(mid))) <= MAX_CHARS:
            lo = mid
        else:
            hi = mid - 1
    return compact_json(build(lo)) if lo > 0 else dump_json_capped(payload)


def as_list(payload: Any) -> list:
    """The API returns a list, or a single object when there is exactly one."""
    if isinstance(payload, list):
        return payload
    return [] if payload in (None, "", {}) else [payload]


def to_iso(value: str | None, name: str) -> str | None:
    """ISO 8601 or epoch milliseconds -> ISO 8601 UTC (what the API takes)."""
    if not value:
        return None
    text = str(value).strip()
    if text.isdigit():
        number = int(text)
        seconds = number / 1000 if number > 10_000_000_000 else number
        return datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as e:
        raise ValueError(f"{name} must be an ISO 8601 time or epoch milliseconds (got {value!r}).") from e
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _location(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    parts = [value.get(k) for k in ("city", "region", "country")]
    text = ", ".join(p for p in parts if isinstance(p, str) and p)
    return text or None


def triage(event: Any) -> Any:
    """Keep the fields an analyst needs to triage one event."""
    if not isinstance(event, dict) or "time" not in event:
        return event
    slim = {k: event[k] for k in _TRIAGE_FIELDS if event.get(k) is not None}
    location = _location(event.get("location"))
    if location:
        slim["location"] = location
    return slim


def shape_events(payload: Any, verbose: bool | None) -> Any:
    """Triage-trim event lists and Elasticsearch hits unless verbose is set."""
    if verbose:
        return payload
    if isinstance(payload, list):
        return {"events": [triage(e) for e in payload], "count": len(payload), "note": "Triage fields only; verbose=true for raw events."}
    if isinstance(payload, dict):
        hits = payload.get("hits")
        inner = hits.get("hits") if isinstance(hits, dict) else None
        if isinstance(inner, list):
            trimmed = [
                {**h, "_source": triage(h["_source"])} if isinstance(h, dict) and isinstance(h.get("_source"), dict) else h
                for h in inner
            ]
            return {**payload, "hits": {**hits, "hits": trimmed}, "note": "Triage fields only; verbose=true for raw events."}
        if "time" in payload:
            return triage(payload)
    return payload


async def run_tool(
    name: str,
    client_factory: ClientFactory,
    action: Callable[[SaasAlertsClient], Awaitable[Any]],
) -> str:
    """Resolve the caller's client, run ``action``, and always return a string.

    Errors never escape as exceptions: they become the standard error envelope.
    """
    client = client_factory()
    if client is None:
        return NOT_CONFIGURED
    started = time.monotonic()
    try:
        result = await action(client)
    except SaasAlertsError as e:
        logger.info("tool=%s outcome=error status=%s ms=%d", name, e.status_code, _ms(started))
        return e.to_envelope()
    except ValueError as e:
        logger.info("tool=%s outcome=invalid_argument ms=%d", name, _ms(started))
        return error_envelope("invalid_argument", str(e), False)
    except Exception as e:  # noqa: BLE001 - tools must never raise
        logger.warning("tool=%s outcome=unexpected error=%s ms=%d", name, type(e).__name__, _ms(started))
        return error_envelope("upstream_error", f"Unexpected error: {type(e).__name__}", True)
    logger.info("tool=%s outcome=ok ms=%d", name, _ms(started))
    if result is None:
        result = {"result": None, "note": "SaaS Alerts returned an empty response."}
    return result if isinstance(result, str) else dump_json_capped(result)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
