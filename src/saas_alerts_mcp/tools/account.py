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
"""The partner account: profile, branding, users, billing and scheduled reports."""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import SaasAlertsClient
from ._common import (
    DESTRUCTIVE,
    READ_ONLY,
    WRITES,
    ClientFactory,
    Confirm,
    as_list,
    run_tool,
)

_BRANDING_FIELDS = {"reportOptions", "display", "color", "logo"}
_REPORT_FIELDS = {"reportName", "reportId", "customerName", "frequency", "recipients", "branding", "metadata"}

ReportId = Annotated[
    str, Field(description="Scheduled report id (scheduledReportId from saas_alerts_reports_list_scheduled).", min_length=1)
]


def _checked(body: dict[str, Any], allowed: set[str], what: str) -> dict[str, Any]:
    if not body:
        raise ValueError(f"body has no {what} fields.")
    unknown = sorted(set(body) - allowed)
    if unknown:
        raise ValueError(f"Unknown {what} field(s): {', '.join(unknown)}; allowed: {', '.join(sorted(allowed))}.")
    return body


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_partner_get_profile() -> str:
        """Get the partner (MSP) profile: name, plan, settings and branding."""

        async def action(client: SaasAlertsClient) -> Any:
            return await client.get("reports/partners/profile")

        return await run_tool("saas_alerts_partner_get_profile", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def saas_alerts_partner_update_branding(
        body: Annotated[
            dict[str, Any],
            Field(
                description='Branding for reports: {"display": 0 or 1, "color": "#RRGGBB", "logo": image URL or data, '
                '"reportOptions": {"hideSaasAlertsCoBranding": bool}}. Replaces the current branding.'
            ),
        ],
    ) -> str:
        """Set the partner's report branding (logo, colour, co-branding). Only when the user explicitly asks."""

        async def action(client: SaasAlertsClient) -> Any:
            result = await client.post("reports/partners/branding", _checked(body, _BRANDING_FIELDS, "branding"))
            return result if result else {"updated": True}

        return await run_tool("saas_alerts_partner_update_branding", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_users_get_msp() -> str:
        """Get the MSP user the API key belongs to."""

        async def action(client: SaasAlertsClient) -> Any:
            return await client.get("reports/msp-user")

        return await run_tool("saas_alerts_users_get_msp", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_users_list_partner() -> str:
        """List the partner's own users (people who sign in to SaaS Alerts)."""

        async def action(client: SaasAlertsClient) -> dict:
            users = as_list(await client.get("reports/partnerUsers"))
            return {"users": users, "count": len(users)}

        return await run_tool("saas_alerts_users_list_partner", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_billing_list_dates() -> str:
        """List the billing periods that have billing details."""

        async def action(client: SaasAlertsClient) -> Any:
            return as_list(await client.get("reports/billing-dates"))

        return await run_tool("saas_alerts_billing_list_dates", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_billing_get_details(
        billing_date: Annotated[
            str, Field(description="Billing period as returned by saas_alerts_billing_list_dates.", min_length=1)
        ],
    ) -> str:
        """Get billing details (billed customers and seats) for one billing period."""

        async def action(client: SaasAlertsClient) -> Any:
            return await client.get("reports/billing-details", {"billingDate": billing_date.strip()})

        return await run_tool("saas_alerts_billing_get_details", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_reports_list_scheduled() -> str:
        """List scheduled reports with their recipients and frequency."""

        async def action(client: SaasAlertsClient) -> dict:
            reports = as_list(await client.get("reports/scheduled-report"))
            return {"reports": reports, "count": len(reports)}

        return await run_tool("saas_alerts_reports_list_scheduled", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_reports_get_scheduled(report_id: ReportId) -> str:
        """Get one scheduled report by id."""

        async def action(client: SaasAlertsClient) -> Any:
            return await client.get(f"reports/scheduled-report/{report_id.strip()}")

        return await run_tool("saas_alerts_reports_get_scheduled", client_factory, action)

    @mcp.tool(annotations=WRITES)
    async def saas_alerts_reports_create_scheduled(
        body: Annotated[
            dict[str, Any],
            Field(
                description='Scheduled report: {"reportName", "reportId" (report type), "customerName", "frequency", '
                '"recipients": {"to": [emails], "cc": [...], "bcc": [...]}, "branding", "metadata"}.'
            ),
        ],
    ) -> str:
        """Schedule a report to be emailed regularly. Only when the user explicitly asks."""

        async def action(client: SaasAlertsClient) -> Any:
            return await client.post("reports/scheduled-report", _checked(body, _REPORT_FIELDS, "scheduled report"))

        return await run_tool("saas_alerts_reports_create_scheduled", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def saas_alerts_reports_delete_scheduled(report_id: ReportId, confirm: Confirm = None) -> str:
        """Delete a scheduled report. Irreversible: only when the user explicitly asks, with confirm=true."""

        async def action(client: SaasAlertsClient) -> Any:
            if confirm is not True:
                raise ValueError("Deleting a scheduled report is irreversible; ask the user, then call again with confirm=true.")
            result = await client.delete(f"reports/scheduled-report/{report_id.strip()}")
            return result if result else {"deleted": True, "report_id": report_id.strip()}

        return await run_tool("saas_alerts_reports_delete_scheduled", client_factory, action)
