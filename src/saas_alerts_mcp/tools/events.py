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
    Verbose,
    as_list,
    compact,
    from_alias,
    run_tool,
    shape_events,
    to_iso,
)

AlertStatus = Annotated[Literal["critical", "medium", "low"] | None, Field(description="Only events of this severity.")]
EventTypes = Annotated[
    list[str] | None,
    Field(
        description="Event types (jointType), e.g. login.failure, login.failure.3.attempts, file.sharing.external, "
        "oauth.granted.permission, new.device, user.promoted.to.admin, outside.own.location, account.locks."
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
        """Query security events by customer, severity, type, user and time range."""

        async def action(client: SaasAlertsClient) -> Any:
            params = _filters(customer_id, alert_status, event_type, start_date, end_date, user_email) | compact(
                {"size": size or 50, "from": from_, "timeSort": time_sort}
            )
            return shape_events(as_list(await client.get("reports/events", params)), verbose)

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
            return await client.get("reports/events/count", _filters(customer_id, alert_status, event_type, start_date, end_date))

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
            return shape_events(await client.post("reports/events/query", _search_body(query, scroll)), verbose)

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
            return shape_events(await client.post("reports/events/scroll", body), verbose)

        return await run_tool("saas_alerts_events_scroll", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_recommended_actions() -> str:
        """List the recommended response for each event type (what an analyst should do)."""

        async def action(client: SaasAlertsClient) -> Any:
            return as_list(await client.get("reports/alert-recommended-actions"))

        return await run_tool("saas_alerts_recommended_actions", client_factory, action)
