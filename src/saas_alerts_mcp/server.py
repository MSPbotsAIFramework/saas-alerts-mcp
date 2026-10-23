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
"""FastMCP factory and the per-request credential middleware."""

import contextvars
import re
import uuid
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ._arguments import EnvelopeFastMCP
from .api_client import SaasAlertsClient, SaasAlertsCredentials
from .config import Settings

HEADER_API_KEY = "X-SaaS-Alerts-API-Key"

_PLACEHOLDER = re.compile(r"^\$\{.*\}$")

# Per-request isolation: the middleware sets these for the duration of one
# HTTP request and resets them in `finally`. Nothing credential-related is
# ever stored at module level.
_credentials_var: contextvars.ContextVar[SaasAlertsCredentials | None] = contextvars.ContextVar(
    "saas_alerts_credentials", default=None
)
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("saas_alerts_request_id", default="-")

INSTRUCTIONS = (
    "SaaS Alerts monitors an MSP's customers' Microsoft 365, Google Workspace, "
    "Salesforce and Dropbox tenants and raises security events (failed and "
    "foreign logins, external file sharing, OAuth grants, admin changes).\n"
    "Usage:\n"
    "- Customers: saas_alerts_customers_list gives customer ids for the "
    "customer_id filters.\n"
    "- Events: saas_alerts_events_query(customer_id, alert_status, event_type, "
    "start_date/end_date, size/from) and saas_alerts_events_count; events are "
    "compacted to triage fields unless verbose=true.\n"
    "- Elasticsearch: saas_alerts_events_query_advanced / count_advanced take "
    "a search body (query, aggs, size, sort); pass scroll (e.g. 1m) to get a "
    "scroll id for saas_alerts_events_scroll.\n"
    "- Devices: saas_alerts_devices_list_orgs gives organization ids for the "
    "device tools.\n"
    "- saas_alerts_recommended_actions explains how to respond to each event "
    "type.\n"
    "Creating, changing or deleting customers, whitelists, scheduled reports "
    "and branding change the partner account: call those tools only when the "
    "user explicitly asks. Deletes need confirm=true."
)


def get_client_from_context() -> SaasAlertsClient | None:
    """The client for the current request, or None outside a request."""
    credentials = _credentials_var.get()
    if credentials is None:
        return None
    return SaasAlertsClient(credentials)


def _clean(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text or _PLACEHOLDER.match(text):
        return None
    return text


class GatewayCredentialsMiddleware:
    """Reads X-SaaS-Alerts-API-Key on /mcp requests into the request context; 401 without it."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        api_key = _clean(request.headers.get(HEADER_API_KEY))
        if not api_key:
            await JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": f"Send the SaaS Alerts API key in the {HEADER_API_KEY} header",
                    "required_headers": [HEADER_API_KEY],
                },
                status_code=401,
            )(scope, receive, send)
            return

        request_id = (request.headers.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex[:12]
        creds_token = _credentials_var.set(SaasAlertsCredentials(api_key=api_key))
        rid_token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send)
        finally:
            _credentials_var.reset(creds_token)
            request_id_var.reset(rid_token)


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server and register every tool."""
    mcp = EnvelopeFastMCP(
        name="saas-alerts-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    client_factory: Callable[[], SaasAlertsClient | None] = get_client_from_context

    from .tools import account, customers, devices, events, navigation

    for module in (navigation, account, customers, devices, events):
        module.register(mcp, client_factory)

    return mcp
