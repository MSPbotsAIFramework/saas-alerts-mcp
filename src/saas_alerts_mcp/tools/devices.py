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
"""Unify devices: endpoints mapped (or not) to SaaS user accounts."""

from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import SaasAlertsClient
from ._common import READ_ONLY, ClientFactory, as_list, run_tool

OrgIds = Annotated[
    list[str], Field(description="Device organization ids (from saas_alerts_devices_list_orgs).", min_length=1)
]


def _ids(values: list[str]) -> list[str]:
    ids = [v.strip() for v in values if v and v.strip()]
    if not ids:
        raise ValueError("organization_ids must contain at least one id.")
    return ids


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_devices_list_orgs() -> str:
        """List the device organizations (from connected RMM / PSA tools) and their ids."""

        async def action(client: SaasAlertsClient) -> dict:
            orgs = as_list(await client.get("reports/devices-organizations"))
            return {"organizations": orgs, "count": len(orgs)}

        return await run_tool("saas_alerts_devices_list_orgs", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_devices_list_mapped(organization_ids: OrgIds) -> str:
        """List devices already mapped to SaaS user accounts in the given organizations."""

        async def action(client: SaasAlertsClient) -> dict:
            devices = as_list(await client.get("reports/unify-mapped-devices-by-account", {"organizationIds": _ids(organization_ids)}))
            return {"devices": devices, "count": len(devices)}

        return await run_tool("saas_alerts_devices_list_mapped", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_devices_list_unmapped(
        organization_ids: OrgIds,
        confidence: Annotated[
            float | None, Field(description="Minimum confidence (0-1) of mapping suggestions (default 0: all).", ge=0, le=1)
        ] = None,
    ) -> str:
        """List devices not yet mapped to a user account, with suggested matches."""

        async def action(client: SaasAlertsClient) -> dict:
            params = {"organizationIds": _ids(organization_ids), "confidence": confidence if confidence is not None else 0}
            devices = as_list(await client.get("reports/unify-unmapped-devices-by-account", params))
            return {"devices": devices, "count": len(devices)}

        return await run_tool("saas_alerts_devices_list_unmapped", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_devices_list_ignored(organization_ids: OrgIds) -> str:
        """List devices excluded from account mapping in the given organizations."""

        async def action(client: SaasAlertsClient) -> dict:
            devices = as_list(await client.get("reports/unify-ignored-devices", {"organizationIds": _ids(organization_ids)}))
            return {"devices": devices, "count": len(devices)}

        return await run_tool("saas_alerts_devices_list_ignored", client_factory, action)
