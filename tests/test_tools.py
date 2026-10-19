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
"""tools/list snapshot, event shaping and error-envelope mapping. No network access."""

import asyncio
import json

import pytest

from saas_alerts_mcp.api_client import SaasAlertsError
from saas_alerts_mcp.server import INSTRUCTIONS, create_mcp_server
from saas_alerts_mcp.tools._common import shape_events, to_iso

# Tool names are a public contract: existing agents and tenant connections
# depend on them. Changing this snapshot is a breaking change.
EXPECTED_TOOLS: dict[str, set[str]] = {
    "saas_alerts_navigate": {"domain"},
    "saas_alerts_status": set(),
    "saas_alerts_billing_get_details": {"billing_date"},
    "saas_alerts_billing_list_dates": set(),
    "saas_alerts_customers_list": set(),
    "saas_alerts_customers_get": {"customer_id"},
    "saas_alerts_customers_create": {"body"},
    "saas_alerts_customers_update": {"customer_id", "body"},
    "saas_alerts_customers_delete": {"customer_id"},
    "saas_alerts_customers_set_whitelists": {"customer_id", "body"},
    "saas_alerts_customers_set_account_whitelists": {"customer_id", "body"},
    "saas_alerts_devices_list_mapped": {"organization_ids"},
    "saas_alerts_devices_list_unmapped": {"organization_ids"},
    "saas_alerts_devices_list_ignored": {"organization_ids"},
    "saas_alerts_devices_list_orgs": set(),
    "saas_alerts_events_query": set(),
    "saas_alerts_events_count": set(),
    "saas_alerts_events_query_advanced": {"query"},
    "saas_alerts_events_count_advanced": {"query"},
    "saas_alerts_events_scroll": {"scroll_id"},
    "saas_alerts_recommended_actions": set(),
    "saas_alerts_partner_get_profile": set(),
    "saas_alerts_partner_update_branding": {"body"},
    "saas_alerts_reports_list_scheduled": set(),
    "saas_alerts_reports_get_scheduled": {"report_id"},
    "saas_alerts_reports_create_scheduled": {"body"},
    "saas_alerts_reports_delete_scheduled": {"report_id"},
    "saas_alerts_users_get_msp": set(),
    "saas_alerts_users_list_partner": set(),
    "saas_alerts_users_list_by_customer": {"customer_id"},
}
WRITE_TOOLS = {
    "saas_alerts_customers_create",
    "saas_alerts_customers_update",
    "saas_alerts_customers_delete",
    "saas_alerts_customers_set_whitelists",
    "saas_alerts_customers_set_account_whitelists",
    "saas_alerts_partner_update_branding",
    "saas_alerts_reports_create_scheduled",
    "saas_alerts_reports_delete_scheduled",
}
# Deletes, and writes that replace existing settings wholesale.
DESTRUCTIVE = {
    "saas_alerts_customers_delete",
    "saas_alerts_customers_set_whitelists",
    "saas_alerts_customers_set_account_whitelists",
    "saas_alerts_partner_update_branding",
    "saas_alerts_reports_delete_scheduled",
}


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in asyncio.run(create_mcp_server().list_tools())}


def test_tool_names_are_stable(tools):
    assert set(tools) == set(EXPECTED_TOOLS)


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_required_params(tools, name):
    assert set(tools[name].inputSchema.get("required", [])) == EXPECTED_TOOLS[name]


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_description_budget(tools, name):
    description = (tools[name].description or "").strip()
    assert description, f"{name} has no description"
    assert len(description) <= 500
    assert len(description.splitlines()[0]) <= 100


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_annotations_match_side_effects(tools, name):
    annotations = tools[name].annotations
    assert annotations.readOnlyHint is (name not in WRITE_TOOLS)
    assert bool(annotations.destructiveHint) is (name in DESTRUCTIVE)


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
def test_write_tools_say_when_to_use_them(tools, name):
    assert "explicitly asks" in tools[name].description


def test_events_query_takes_from(tools):
    properties = tools["saas_alerts_events_query"].inputSchema["properties"]
    assert "from" in properties
    assert "from_" not in properties


def test_instructions_budget():
    assert len(INSTRUCTIONS) <= 1500


@pytest.mark.parametrize(
    "status,code,retryable",
    [(401, "unauthorized", False), (403, "unauthorized", False), (404, "not_found", False),
     (400, "invalid_argument", False), (429, "rate_limited", True), (500, "upstream_error", True), (0, "upstream_error", True)],
)
def test_error_envelope(status, code, retryable):
    envelope = json.loads(SaasAlertsError(status, "boom").to_envelope())
    assert envelope == {"error": {"code": code, "message": "boom", "retryable": retryable}}


def test_tool_without_credentials_returns_not_configured():
    content, _ = asyncio.run(create_mcp_server().call_tool("saas_alerts_status", {}))
    assert json.loads(content[0].text)["error"]["code"] == "not_configured"


def test_navigate_is_local():
    content, _ = asyncio.run(create_mcp_server().call_tool("saas_alerts_navigate", {"domain": "devices"}))
    assert "saas_alerts_devices_list_unmapped" in json.loads(content[0].text)["tools"]


@pytest.mark.parametrize(
    "value,expected",
    [("1767225600000", "2026-01-01T00:00:00.000Z"), ("1767225600", "2026-01-01T00:00:00.000Z"),
     ("2026-01-01", "2026-01-01T00:00:00.000Z"), ("2026-01-01T08:00:00+08:00", "2026-01-01T00:00:00.000Z"),
     (None, None)],
)
def test_to_iso(value, expected):
    assert to_iso(value, "start_date") == expected


def test_to_iso_rejects_garbage():
    with pytest.raises(ValueError):
        to_iso("yesterday", "start_date")


EVENT = {
    "time": "2026-01-01T00:00:00Z",
    "jointType": "login.failure",
    "alertStatus": "medium",
    "userEmail": "user@example.com",
    "ip": "203.0.113.5",
    "location": {"city": "Austin", "region": "Texas", "country": "US", "lat": 30.2},
    "raw": {"huge": "x" * 1000},
}


def test_shape_events_trims_lists():
    shaped = shape_events([EVENT], None)
    assert shaped["count"] == 1
    assert shaped["events"][0] == {
        "time": "2026-01-01T00:00:00Z",
        "jointType": "login.failure",
        "alertStatus": "medium",
        "userEmail": "user@example.com",
        "ip": "203.0.113.5",
        "location": "Austin, Texas, US",
    }


def test_shape_events_trims_elasticsearch_hits():
    payload = {"_scroll_id": "abc", "hits": {"total": {"value": 1}, "hits": [{"_id": "1", "_source": EVENT}]}}
    shaped = shape_events(payload, False)
    assert shaped["_scroll_id"] == "abc"
    assert "raw" not in shaped["hits"]["hits"][0]["_source"]


def test_shape_events_verbose_returns_raw():
    assert shape_events([EVENT], True) == [EVENT]
