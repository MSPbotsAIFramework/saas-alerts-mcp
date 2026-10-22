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
"""Security events: filtered queries, counts, raw Elasticsearch searches and scrolling."""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import SaasAlertsClient
from ._common import (
    READ_ONLY,
    ClientFactory,
    Limit,
    Offset,
    Verbose,
    as_list,
    compact,
    es_capped,
    from_alias,
    local_page,
    run_tool,
    shape_events,
    to_iso,
)

AlertStatus = Annotated[Literal["critical", "medium", "low"] | None, Field(description="Only events of this severity.")]
EventTypes = Annotated[
    list[str] | None,
    Field(
        description="Event types: the exact, full jointType value, e.g. login.failure, login.success, "
        "enterprise.application.login.success, file.sharing.external, oauth.granted.permission, new.device, "
        "user.promoted.to.admin, outside.own.location, account.locks."
    ),
]
StartDate = Annotated[str | None, Field(description="Range start: ISO 8601 or epoch milliseconds.")]
EndDate = Annotated[str | None, Field(description="Range end: ISO 8601 or epoch milliseconds.")]
Search = Annotated[
    dict[str, Any],
    Field(
        description="Elasticsearch search body: query (required), and optionally size, from, sort, aggs, _source. "
        'Do not wrap it in "body". Example: {"size": 0, "query": {"bool": {"filter": [{"term": '
        '{"jointType": "login.failure"}}]}}, "aggs": {"ips": {"terms": {"field": "ip", "size": 25}}}}. '
        'Keyword fields use .keyword, e.g. {"term": {"alertStatus.keyword": "critical"}}.'
    ),
]


def _filters(
    customer_id: str | None,
    alert_status: str | None,
    event_type: list[str] | None,
    start_date: str | None,
    end_date: str | None,
    user_email: str | None = None,
) -> dict:
    return compact(
        {
            "customerId": customer_id,
            "userEmail": user_email,
            "alertStatus": alert_status,
            "eventType": [t.strip() for t in event_type if t.strip()] if event_type else None,
            "start": to_iso(start_date, "start_date"),
            "end": to_iso(end_date, "end_date"),
        }
    )


def _es(result: Any) -> Any:
    """Elasticsearch responses keep their records in hits.hits: cap them there (see es_capped)."""
    if isinstance(result, dict) and isinstance(result.get("hits"), dict) and isinstance(result["hits"].get("hits"), list):
        return es_capped(result)
    return result


def _recommendation_records(payload: Any) -> list[dict]:
    """One record per event type, whether the API sends a mapping or a list."""
    if isinstance(payload, dict) and not any(k in payload for k in ("event_type", "eventType", "jointType")):
        records = []
        for key, value in payload.items():
            body = value if isinstance(value, dict) else {"recommended_action": value}
            records.append({"event_type": key, **body})
        return records
    rows = as_list(payload)
    return [
        ({"event_type": r.get("event_type") or r.get("eventType") or r.get("jointType"), **r} if isinstance(r, dict) else {"recommended_action": r})
        for r in rows
    ]


def _es_query(
    customer_id: str | None,
    alert_status: str | None,
    types: list[str],
    start_date: str | None,
    end_date: str | None,
    user_email: str | None = None,
) -> dict:
    """The same filters as GET reports/events, as an Elasticsearch bool query.

    Field names checked on a live account: customer.id, alertStatus, jointType, user.name, time.
    """
    filters: list[dict] = []
    if customer_id and customer_id.strip():
        filters.append({"term": {"customer.id": customer_id.strip()}})
    if alert_status:
        filters.append({"term": {"alertStatus": alert_status}})
    if types:
        filters.append({"terms": {"jointType": types}})
    if user_email and user_email.strip():
        filters.append({"term": {"user.name": user_email.strip()}})
    window = compact({"gte": to_iso(start_date, "start_date"), "lte": to_iso(end_date, "end_date")})
    if window:
        filters.append({"range": {"time": window}})
    return {"bool": {"filter": filters}} if filters else {"match_all": {}}


def _search_body(search: dict[str, Any], scroll: str | None = None, size: int | None = None) -> dict:
    if not isinstance(search, dict) or "query" not in search:
        raise ValueError('query must be an Elasticsearch search body containing "query".')
    if set(search) == {"body"}:
        raise ValueError('Pass the search body itself, not wrapped in "body".')
    return compact({"body": search, "scroll": scroll, "size": size})


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    @from_alias
    async def saas_alerts_events_query(
        customer_id: Annotated[str | None, Field(description="Only events of this customer.")] = None,
        alert_status: AlertStatus = None,
        event_type: EventTypes = None,
        user_email: Annotated[str | None, Field(description="Only events of this user (email / UPN).")] = None,
        start_date: StartDate = None,
        end_date: EndDate = None,
        size: Annotated[int | None, Field(description="Events to return (default 50, max 200).", ge=1, le=200)] = None,
        from_: Annotated[int | None, Field(alias="from", description="Events to skip.", ge=0)] = None,
        time_sort: Annotated[Literal["asc", "desc"] | None, Field(description="Order by event time.")] = None,
        verbose: Verbose = None,
    ) -> str:
        """Query security events by customer, severity, type, user and time range.

        has_more / next_from say whether to call again (pass next_from as from); the API gives no total,
        use saas_alerts_events_count for it.
        """

        async def action(client: SaasAlertsClient) -> Any:
            page_size, start = size or 50, from_ or 0
            types = [t.strip() for t in event_type or [] if t.strip()]
            total = None
            if time_sort or len(types) > 1:
                # GET reports/events ignores timeSort and rejects several eventType values; the
                # Elasticsearch search sorts and filters correctly (checked against events_count).
                body = {"size": page_size, "from": start, "query": _es_query(customer_id, alert_status, types, start_date, end_date, user_email)}
                if time_sort:
                    body["sort"] = [{"time": time_sort}]
                payload = await client.post("reports/events/query", _search_body(body))
                hits = payload.get("hits") if isinstance(payload, dict) and isinstance(payload.get("hits"), dict) else {}
                events = [h["_source"] for h in hits.get("hits") or [] if isinstance(h, dict) and isinstance(h.get("_source"), dict)]
                found = hits.get("total")
                if isinstance(found, dict) and found.get("relation") == "eq" and isinstance(found.get("value"), int):
                    total = found["value"]
            else:
                params = _filters(customer_id, alert_status, types or None, start_date, end_date, user_email) | compact(
                    {"size": page_size, "from": from_}
                )
                events = as_list(await client.get("reports/events", params))
            shaped = shape_events(events, False)
            result = {"events": events if verbose else shaped["events"], "count": len(events)}
            if not verbose:
                result["note"] = shaped["note"]
            # GET returns a plain array: a full page means there may be more.
            result["has_more"] = start + len(events) < total if total is not None else len(events) >= page_size
            if total is not None:
                result["total"] = total
            if result["has_more"]:
                result["next_from"] = start + len(events)
            return result | {"_resume": {"key": "next_from", "start": start}}

        return await run_tool("saas_alerts_events_query", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_events_count(
        customer_id: Annotated[str | None, Field(description="Only events of this customer.")] = None,
        alert_status: AlertStatus = None,
        event_type: EventTypes = None,
        start_date: StartDate = None,
        end_date: EndDate = None,
    ) -> str:
        """Count security events matching filters without fetching them."""

        async def action(client: SaasAlertsClient) -> Any:
            types = [t.strip() for t in event_type or [] if t.strip()]
            if len(types) > 1:
                # The GET count rejects several eventType values; the Elasticsearch count does not.
                query = {"query": _es_query(customer_id, alert_status, types, start_date, end_date)}
                counted = await client.post("reports/events/count/query", _search_body(query))
                return {"total": counted.get("count") if isinstance(counted, dict) else counted}
            return await client.get("reports/events/count", _filters(customer_id, alert_status, types or None, start_date, end_date))

        return await run_tool("saas_alerts_events_count", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_events_query_advanced(
        query: Search,
        verbose: Verbose = None,
        scroll: Annotated[
            str | None, Field(description="Keep a scroll cursor alive this long (e.g. 1m) to page with saas_alerts_events_scroll.")
        ] = None,
    ) -> str:
        """Run an Elasticsearch search over the events index (filters, aggregations, sorting)."""

        async def action(client: SaasAlertsClient) -> Any:
            return _es(shape_events(await client.post("reports/events/query", _search_body(query, scroll)), verbose))

        return await run_tool("saas_alerts_events_query_advanced", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_events_count_advanced(query: Search) -> str:
        """Count events matching an Elasticsearch query without fetching them."""

        async def action(client: SaasAlertsClient) -> Any:
            return await client.post("reports/events/count/query", _search_body(query))

        return await run_tool("saas_alerts_events_count_advanced", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_events_scroll(
        scroll_id: Annotated[str, Field(description="_scroll_id from the previous page.", min_length=1)],
        verbose: Verbose = None,
        scroll: Annotated[str | None, Field(description="Keep the cursor alive this long for the next page (default 1m).")] = None,
    ) -> str:
        """Get the next page of an Elasticsearch query started with scroll."""

        async def action(client: SaasAlertsClient) -> Any:
            body = {"scrollId": scroll_id.strip(), "scroll": scroll or "1m"}
            return _es(shape_events(await client.post("reports/events/scroll", body), verbose))

        return await run_tool("saas_alerts_events_scroll", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_recommended_actions(
        event_type: Annotated[str | None, Field(description="Only this event type (jointType), e.g. login.failure.")] = None,
        offset: Offset = None,
        limit: Limit = None,
    ) -> str:
        """List the recommended response for each event type (what an analyst should do).

        One record per event type; pass event_type for one, or continue with offset=next_offset. A full
        list may shorten long texts to fit; event_type or a small limit returns them in full.
        """

        async def action(client: SaasAlertsClient) -> Any:
            records = _recommendation_records(await client.get("reports/alert-recommended-actions"))
            if event_type and event_type.strip():
                wanted = event_type.strip().lower()
                records = [r for r in records if str(r.get("event_type", "")).lower() == wanted]
            return local_page(records, "recommended_actions", offset, limit)

        return await run_tool("saas_alerts_recommended_actions", client_factory, action)
