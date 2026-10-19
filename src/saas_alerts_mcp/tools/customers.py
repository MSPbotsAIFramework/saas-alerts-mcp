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
"""Customers (the MSP's monitored organisations), their users and their whitelists."""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import SaasAlertsClient
from ._common import (
    DESTRUCTIVE,
    READ_ONLY,
    WRITES,
    WRITES_IDEMPOTENT,
    ClientFactory,
    Confirm,
    CustomerId,
    as_list,
    run_tool,
)

_CUSTOMER_FIELDS = {"name", "email"}
_WHITELIST_FIELDS = {"inheritanceWl", "asnList", "ipRanges", "countries"}

CustomerBody = Annotated[
    dict[str, Any], Field(description='Customer fields: {"name": ..., "email": ...} (name required to create).')
]
WhitelistBody = Annotated[
    dict[str, Any],
    Field(
        description='Whitelist: {"inheritanceWl": bool (inherit the partner whitelist), "asnList": [ASN entries], '
        '"ipRanges": [IP range entries], "countries": ["US", ...]}. Replaces the current whitelist.'
    ),
]


def _checked(body: dict[str, Any], allowed: set[str], what: str) -> dict[str, Any]:
    unknown = sorted(set(body) - allowed)
    if unknown:
        raise ValueError(f"Unknown {what} field(s): {', '.join(unknown)}; allowed: {', '.join(sorted(allowed))}.")
    return body


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_customers_list() -> str:
        """List customers (monitored organisations) with their ids and connected products."""

        async def action(client: SaasAlertsClient) -> dict:
            customers = as_list(await client.get("customers"))
            return {"customers": customers, "count": len(customers)}

        return await run_tool("saas_alerts_customers_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_customers_get(customer_id: CustomerId) -> str:
        """Get one customer by id."""

        async def action(client: SaasAlertsClient) -> Any:
            return await client.get(f"customers/{customer_id.strip()}")

        return await run_tool("saas_alerts_customers_get", client_factory, action)

    @mcp.tool(annotations=WRITES)
    async def saas_alerts_customers_create(body: CustomerBody) -> str:
        """Create a customer. Only when the user explicitly asks."""

        async def action(client: SaasAlertsClient) -> Any:
            fields = _checked(body, _CUSTOMER_FIELDS, "customer")
            if not str(fields.get("name") or "").strip():
                raise ValueError('body.name is required to create a customer.')
            return await client.post("customers", fields)

        return await run_tool("saas_alerts_customers_create", client_factory, action)

    @mcp.tool(annotations=WRITES_IDEMPOTENT)
    async def saas_alerts_customers_update(customer_id: CustomerId, body: CustomerBody) -> str:
        """Change a customer's name or email; only the fields given change. Only when the user explicitly asks."""

        async def action(client: SaasAlertsClient) -> Any:
            fields = _checked(body, _CUSTOMER_FIELDS, "customer")
            if not fields:
                raise ValueError("Nothing to update: body has no fields.")
            return await client.patch(f"customers/{customer_id.strip()}", fields)

        return await run_tool("saas_alerts_customers_update", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def saas_alerts_customers_delete(customer_id: CustomerId, confirm: Confirm = None) -> str:
        """Delete a customer and stop monitoring it.

        Irreversible: only when the user explicitly asks, with confirm=true.
        """

        async def action(client: SaasAlertsClient) -> Any:
            if confirm is not True:
                raise ValueError("Deleting a customer is irreversible; ask the user, then call again with confirm=true.")
            result = await client.delete(f"customers/{customer_id.strip()}")
            return result if result else {"deleted": True, "customer_id": customer_id.strip()}

        return await run_tool("saas_alerts_customers_delete", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def saas_alerts_customers_set_whitelists(customer_id: CustomerId, body: WhitelistBody) -> str:
        """Set a customer's trusted ASNs, IP ranges and countries. Only when the user explicitly asks."""

        async def action(client: SaasAlertsClient) -> Any:
            return await client.post(f"customers/{customer_id.strip()}/whitelists", _checked(body, _WHITELIST_FIELDS, "whitelist"))

        return await run_tool("saas_alerts_customers_set_whitelists", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def saas_alerts_customers_set_account_whitelists(customer_id: CustomerId, body: WhitelistBody) -> str:
        """Set the whitelist applied to a customer's user accounts. Only when the user explicitly asks."""

        async def action(client: SaasAlertsClient) -> Any:
            return await client.post(
                f"customers/{customer_id.strip()}/accounts/whitelists", _checked(body, _WHITELIST_FIELDS, "whitelist")
            )

        return await run_tool("saas_alerts_customers_set_account_whitelists", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def saas_alerts_users_list_by_customer(customer_id: CustomerId) -> str:
        """List a customer's monitored SaaS user accounts."""

        async def action(client: SaasAlertsClient) -> dict:
            users = as_list(await client.get("reports/users", {"customerId": customer_id.strip()}))
            return {"users": users, "count": len(users)}

        return await run_tool("saas_alerts_users_list_by_customer", client_factory, action)
