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
"""Tool discovery (kept for compatibility) and the connection check."""

from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .._json import compact as to_json
from ..api_client import SaasAlertsClient
from ._common import LOCAL, READ_ONLY, ClientFactory, run_tool

DOMAINS: dict[str, tuple[str, list[str]]] = {
    "events": (
        "Security events: filtered queries and counts, Elasticsearch searches, scrolling, recommended actions.",
        [
            "saas_alerts_events_query",
            "saas_alerts_events_count",
            "saas_alerts_events_query_advanced",
            "saas_alerts_events_count_advanced",
            "saas_alerts_events_scroll",
            "saas_alerts_recommended_actions",
        ],
    ),
    "customers": (
        "Customers: list, get, create, update, delete; IP / ASN / country whitelists.",
        [
            "saas_alerts_customers_list",
            "saas_alerts_customers_get",
            "saas_alerts_customers_create",
            "saas_alerts_customers_update",
            "saas_alerts_customers_delete",
            "saas_alerts_customers_set_whitelists",
            "saas_alerts_customers_set_account_whitelists",
        ],
    ),
    "users": (
        "The signed-in MSP user, partner users, and a customer's monitored accounts.",
        ["saas_alerts_users_get_msp", "saas_alerts_users_list_partner", "saas_alerts_users_list_by_customer"],
    ),
    "devices": (
        "Device organizations and devices mapped, unmapped or ignored for account mapping.",
        [
            "saas_alerts_devices_list_orgs",
            "saas_alerts_devices_list_mapped",
            "saas_alerts_devices_list_unmapped",
            "saas_alerts_devices_list_ignored",
        ],
    ),
    "billing": ("Billing periods and the billing details of one period.", ["saas_alerts_billing_list_dates", "saas_alerts_billing_get_details"]),
    "reports": (
        "Scheduled reports: list, get, create, delete.",
        [
            "saas_alerts_reports_list_scheduled",
            "saas_alerts_reports_get_scheduled",
            "saas_alerts_reports_create_scheduled",
            "saas_alerts_reports_delete_scheduled",
        ],
    ),
    "partner": ("The partner profile and report branding.", ["saas_alerts_partner_get_profile", "saas_alerts_partner_update_branding"]),
}


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=LOCAL)
    async def saas_alerts_navigate(
        domain: Annotated[
            Literal["events", "customers", "users", "devices", "billing", "reports", "partner"],
            Field(description="Area to describe."),
        ],
    ) -> str:
        """Describe the tools of one SaaS Alerts area. All tools are already callable; this changes nothing."""
        summary, tools = DOMAINS[domain]
        return to_json({"domain": domain, "summary": summary, "tools": tools})

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_status() -> str:
        """Check the SaaS Alerts connection (the API key works) and list the tool areas."""

        async def action(client: SaasAlertsClient) -> dict:
            await client.get("reports/msp-user")
            return {
                "connected": True,
                "base_url": client.base_url,
                "domains": {name: summary for name, (summary, _tools) in DOMAINS.items()},
            }

        return await run_tool("saas_alerts_status", client_factory, action)
