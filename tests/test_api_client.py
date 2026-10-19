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
"""Request shapes, event shaping and retries against a mocked SaaS Alerts API."""

import json

import httpx
import pytest

from saas_alerts_mcp import api_client
from saas_alerts_mcp.api_client import (
    SaasAlertsClient,
    SaasAlertsCredentials,
    SaasAlertsError,
)
from saas_alerts_mcp.server import _credentials_var, create_mcp_server

CREDS = SaasAlertsCredentials(api_key="key-123")
PREFIX = "/reportApi/api/v1/"


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(api_client.asyncio, "sleep", instant)


class Recorder:
    """Mock transport: replies by "METHOD path" or path below the API prefix."""

    def __init__(self, routes=None, default=None):
        self.requests: list[httpx.Request] = []
        self.routes = routes or {}
        self.default = default if default is not None else []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path.removeprefix(PREFIX)
        reply = self.routes.get(f"{request.method} {path}", self.routes.get(path, self.default))
        if callable(reply):
            return reply(request)
        return httpx.Response(200, json=reply)

    def calls(self, method: str, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == method and r.url.path == f"{PREFIX}{path}"]


def body(request: httpx.Request):
    return json.loads(request.content) if request.content else None


async def _call(monkeypatch, recorder: Recorder, tool: str, args: dict):
    http = httpx.AsyncClient(transport=httpx.MockTransport(recorder))
    monkeypatch.setattr(api_client, "_get_shared_http_client", lambda: http)
    ctx = _credentials_var.set(CREDS)
    try:
        content, _ = await create_mcp_server().call_tool(tool, args)
    finally:
        _credentials_var.reset(ctx)
    return json.loads(content[0].text)


def _client(recorder: Recorder) -> SaasAlertsClient:
    return SaasAlertsClient(CREDS, httpx.AsyncClient(transport=httpx.MockTransport(recorder)))


# ---- client ----------------------------------------------------------------


async def test_api_key_header_and_url():
    rec = Recorder()
    await _client(rec).get("customers")
    request = rec.requests[0]
    assert str(request.url) == "https://us-central1-the-byway-248217.cloudfunctions.net/reportApi/api/v1/customers"
    assert request.headers["api_key"] == "key-123"
    assert "Authorization" not in request.headers


async def test_error_message_hides_key():
    rec = Recorder({"customers": lambda r: httpx.Response(400, json={"message": "bad key key-123"})})
    with pytest.raises(SaasAlertsError) as err:
        await _client(rec).get("customers")
    assert "key-123" not in err.value.message
    assert err.value.status_code == 400


async def test_quota_message_is_rate_limited():
    rec = Recorder({"customers": lambda r: httpx.Response(403, text="Quota exceeded for this API key")})
    with pytest.raises(SaasAlertsError) as err:
        await _client(rec).get("customers")
    assert err.value.status_code == 429


async def test_get_retries_5xx():
    replies = iter([httpx.Response(503), httpx.Response(200, json=[])])
    rec = Recorder({"customers": lambda r: next(replies)})
    await _client(rec).get("customers")
    assert len(rec.requests) == 2


async def test_writes_are_not_retried_on_5xx():
    rec = Recorder({"POST customers": lambda r: httpx.Response(500, json={"message": "boom"})})
    with pytest.raises(SaasAlertsError):
        await _client(rec).post("customers", {"name": "x"})
    assert len(rec.requests) == 1


async def test_unauthorized_maps_to_envelope(monkeypatch):
    rec = Recorder({"customers": lambda r: httpx.Response(401, json={"message": "Unauthorized"})})
    result = await _call(monkeypatch, rec, "saas_alerts_customers_list", {})
    assert result["error"]["code"] == "unauthorized"


# ---- events ----------------------------------------------------------------

EVENT = {"time": "2026-01-01T00:00:00Z", "jointType": "login.failure", "alertStatus": "medium", "raw": "x" * 500}


async def test_events_query_params(monkeypatch):
    rec = Recorder({"reports/events": [EVENT]})
    args = {"customer_id": "c1", "alert_status": "critical", "event_type": ["login.failure", "new.device"],
            "user_email": "user@example.com", "start_date": "1767225600000", "end_date": "2026-01-02",
            "from": 20, "size": 10, "time_sort": "desc"}
    result = await _call(monkeypatch, rec, "saas_alerts_events_query", args)
    params = rec.requests[0].url.params
    assert params["customerId"] == "c1"
    assert params["alertStatus"] == "critical"
    assert params.get_list("eventType") == ["login.failure", "new.device"]
    assert params["userEmail"] == "user@example.com"
    assert params["start"] == "2026-01-01T00:00:00.000Z"
    assert params["end"] == "2026-01-02T00:00:00.000Z"
    assert (params["from"], params["size"], params["timeSort"]) == ("20", "10", "desc")
    assert result["count"] == 1 and "raw" not in result["events"][0]


async def test_events_query_default_size(monkeypatch):
    rec = Recorder()
    await _call(monkeypatch, rec, "saas_alerts_events_query", {})
    assert rec.requests[0].url.params["size"] == "50"


async def test_events_query_verbose_is_raw(monkeypatch):
    rec = Recorder({"reports/events": [EVENT]})
    result = await _call(monkeypatch, rec, "saas_alerts_events_query", {"verbose": True})
    assert result == [EVENT]


async def test_events_count_has_no_paging(monkeypatch):
    rec = Recorder({"reports/events/count": {"count": 7}})
    result = await _call(monkeypatch, rec, "saas_alerts_events_count", {"alert_status": "low"})
    assert dict(rec.requests[0].url.params) == {"alertStatus": "low"}
    assert result == {"count": 7}


async def test_advanced_query_body_and_scroll(monkeypatch):
    rec = Recorder({"POST reports/events/query": {"_scroll_id": "s1", "hits": {"hits": [{"_id": "1", "_source": EVENT}]}}})
    search = {"query": {"match_all": {}}, "size": 5}
    result = await _call(monkeypatch, rec, "saas_alerts_events_query_advanced", {"query": search, "scroll": "1m"})
    assert body(rec.requests[0]) == {"body": search, "scroll": "1m"}
    assert result["_scroll_id"] == "s1"
    assert "raw" not in result["hits"]["hits"][0]["_source"]


async def test_advanced_query_needs_query_key(monkeypatch):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "saas_alerts_events_query_advanced", {"query": {"body": {"query": {}}}})
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


async def test_count_advanced(monkeypatch):
    rec = Recorder({"POST reports/events/count/query": {"count": 3}})
    search = {"query": {"term": {"jointType": "login.failure"}}}
    await _call(monkeypatch, rec, "saas_alerts_events_count_advanced", {"query": search})
    assert body(rec.requests[0]) == {"body": search}


async def test_scroll_body(monkeypatch):
    rec = Recorder({"POST reports/events/scroll": {"hits": {"hits": []}}})
    await _call(monkeypatch, rec, "saas_alerts_events_scroll", {"scroll_id": " s1 "})
    assert body(rec.requests[0]) == {"scrollId": "s1", "scroll": "1m"}


# ---- customers -------------------------------------------------------------


async def test_customer_create_needs_name(monkeypatch):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "saas_alerts_customers_create", {"body": {"email": "it@example.com"}})
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


async def test_customer_unknown_field_rejected(monkeypatch):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "saas_alerts_customers_update", {"customer_id": "c1", "body": {"nmae": "x"}})
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


async def test_customer_update_is_patch(monkeypatch):
    rec = Recorder({"PATCH customers/c1": {"id": "c1"}})
    await _call(monkeypatch, rec, "saas_alerts_customers_update", {"customer_id": "c1", "body": {"name": "Acme"}})
    assert body(rec.calls("PATCH", "customers/c1")[0]) == {"name": "Acme"}


@pytest.mark.parametrize(
    "tool,args,path",
    [("saas_alerts_customers_delete", {"customer_id": "c1"}, "customers/c1"),
     ("saas_alerts_reports_delete_scheduled", {"report_id": "r1"}, "reports/scheduled-report/r1")],
)
async def test_delete_needs_confirm(monkeypatch, tool, args, path):
    rec = Recorder({f"DELETE {path}": lambda r: httpx.Response(200, content=b"")})
    result = await _call(monkeypatch, rec, tool, args)
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []
    result = await _call(monkeypatch, rec, tool, args | {"confirm": True})
    assert result["deleted"] is True
    assert len(rec.calls("DELETE", path)) == 1


@pytest.mark.parametrize(
    "tool,path",
    [("saas_alerts_customers_set_whitelists", "customers/c1/whitelists"),
     ("saas_alerts_customers_set_account_whitelists", "customers/c1/accounts/whitelists")],
)
async def test_whitelists(monkeypatch, tool, path):
    rec = Recorder({f"POST {path}": {"ok": True}})
    wl = {"inheritanceWl": True, "countries": ["US"]}
    await _call(monkeypatch, rec, tool, {"customer_id": "c1", "body": wl})
    assert body(rec.calls("POST", path)[0]) == wl


async def test_users_by_customer(monkeypatch):
    rec = Recorder({"reports/users": [{"email": "a@example.com"}]})
    result = await _call(monkeypatch, rec, "saas_alerts_users_list_by_customer", {"customer_id": "c1"})
    assert rec.requests[0].url.params["customerId"] == "c1"
    assert result["count"] == 1


# ---- devices ---------------------------------------------------------------


async def test_unmapped_devices_params(monkeypatch):
    rec = Recorder()
    await _call(monkeypatch, rec, "saas_alerts_devices_list_unmapped", {"organization_ids": ["o1", "o2"]})
    params = rec.requests[0].url.params
    assert params.get_list("organizationIds") == ["o1", "o2"]
    assert params["confidence"] == "0"


async def test_mapped_devices_need_ids(monkeypatch):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "saas_alerts_devices_list_mapped", {"organization_ids": [" "]})
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


# ---- account ---------------------------------------------------------------


async def test_billing_details_param(monkeypatch):
    rec = Recorder({"reports/billing-details": {"total": 1}})
    await _call(monkeypatch, rec, "saas_alerts_billing_get_details", {"billing_date": "2026-09"})
    assert rec.requests[0].url.params["billingDate"] == "2026-09"


async def test_branding_fields_checked(monkeypatch):
    rec = Recorder({"POST reports/partners/branding": {}})
    result = await _call(monkeypatch, rec, "saas_alerts_partner_update_branding", {"body": {"colour": "#fff"}})
    assert result["error"]["code"] == "invalid_argument"
    result = await _call(monkeypatch, rec, "saas_alerts_partner_update_branding", {"body": {"color": "#ffffff", "display": 1}})
    assert result == {"updated": True}


async def test_scheduled_report_create(monkeypatch):
    rec = Recorder({"POST reports/scheduled-report": {"scheduledReportId": "r1"}})
    report = {"reportName": "Weekly", "frequency": "weekly", "recipients": {"to": ["it@example.com"]}}
    result = await _call(monkeypatch, rec, "saas_alerts_reports_create_scheduled", {"body": report})
    assert body(rec.requests[0]) == report
    assert result == {"scheduledReportId": "r1"}


async def test_status(monkeypatch):
    rec = Recorder({"reports/msp-user": {"email": "admin@example.com"}})
    result = await _call(monkeypatch, rec, "saas_alerts_status", {})
    assert result["connected"] is True
    assert rec.calls("GET", "reports/msp-user")
