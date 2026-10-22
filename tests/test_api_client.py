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
    # No sort and at most one type: GET reports/events with the documented query parameters.
    rec = Recorder({"reports/events": [EVENT]})
    args = {"customer_id": "c1", "alert_status": "critical", "event_type": ["login.failure"],
            "user_email": "user@example.com", "start_date": "1767225600000", "end_date": "2026-01-02",
            "from": 20, "size": 10}
    result = await _call(monkeypatch, rec, "saas_alerts_events_query", args)
    params = rec.requests[0].url.params
    assert params["customerId"] == "c1"
    assert params["alertStatus"] == "critical"
    assert params.get_list("eventType") == ["login.failure"]
    assert params["userEmail"] == "user@example.com"
    assert params["start"] == "2026-01-01T00:00:00.000Z"
    assert params["end"] == "2026-01-02T00:00:00.000Z"
    assert (params["from"], params["size"]) == ("20", "10") and "timeSort" not in params
    assert result["count"] == 1 and "raw" not in result["events"][0]


async def test_events_query_default_size(monkeypatch):
    rec = Recorder()
    await _call(monkeypatch, rec, "saas_alerts_events_query", {})
    assert rec.requests[0].url.params["size"] == "50"


async def test_events_query_verbose_is_raw(monkeypatch):
    rec = Recorder({"reports/events": [EVENT]})
    result = await _call(monkeypatch, rec, "saas_alerts_events_query", {"verbose": True})
    assert result["events"] == [EVENT] and result["has_more"] is False  # raw events, with paging fields


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
    await _call(monkeypatch, rec, "saas_alerts_customers_update", {"customer_id": "c1", "body": {"name": "Example Client"}})
    assert body(rec.calls("PATCH", "customers/c1")[0]) == {"name": "Example Client"}


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



# ---- PRD-21123: whole lists continue by offset -------------------------------------------------------------
# Checklist: cut lists walked by next_offset return every record once; offset inside / limit / past the end;
# no offset returns every record as before; no retry_page_size when next_offset is exact.

def _wide(i):
    return {"id": f"r{i:04d}", "name": f"Record {i}", **{f"field{k}": f"value {k}" for k in range(40)}}


ORGS = ["tfDpgZTTv3XFsqJF1Tmc", "second-org"]
WHOLE_LISTS = [
    ("saas_alerts_customers_list", "customers", "customers", {}),
    ("saas_alerts_users_list_partner", "reports/partnerUsers", "users", {}),
    ("saas_alerts_users_list_by_customer", "reports/users", "users", {"customer_id": "c1"}),
    ("saas_alerts_reports_list_scheduled", "reports/scheduled-report", "reports", {}),
    ("saas_alerts_devices_list_orgs", "reports/devices-organizations", "organizations", {}),
    ("saas_alerts_devices_list_mapped", "reports/unify-mapped-devices-by-account", "devices", {"organization_ids": ORGS}),
    ("saas_alerts_devices_list_unmapped", "reports/unify-unmapped-devices-by-account", "devices", {"organization_ids": ORGS}),
    ("saas_alerts_devices_list_ignored", "reports/unify-ignored-devices", "devices", {"organization_ids": ORGS}),
]


@pytest.mark.parametrize("tool,path,key,args", WHOLE_LISTS)
async def test_cut_whole_lists_continue_by_next_offset(monkeypatch, tool, path, key, args):
    rows = [_wide(i) for i in range(134)]
    rec = Recorder({path: rows})
    ids, cut, call_args, calls = [], 0, dict(args), 0
    while True:
        out = await _call(monkeypatch, rec, tool, call_args)
        calls += 1
        assert "retry_page_size" not in out
        cut += bool(out.get("truncated"))
        ids += [r["id"] for r in out[key]]
        if out.get("next_offset") is None:
            break
        call_args = args | {"offset": out["next_offset"]}
        assert calls < 60
    assert cut > 0 and ids == [r["id"] for r in rows]


@pytest.mark.parametrize("tool,path,key,args", WHOLE_LISTS)
async def test_offset_limit_and_past_the_end(monkeypatch, tool, path, key, args):
    rows = [{"id": f"r{i}"} for i in range(38)]
    rec = Recorder({path: rows})
    page = await _call(monkeypatch, rec, tool, args | {"offset": 10, "limit": 3})
    assert [r["id"] for r in page[key]] == ["r10", "r11", "r12"]
    assert (page["next_offset"], page["total"], page["has_more"]) == (13, 38, True)
    past = await _call(monkeypatch, rec, tool, args | {"offset": 100})
    assert (past[key], past["has_more"], past.get("next_offset")) == ([], False, None)
    whole = await _call(monkeypatch, rec, tool, args)
    assert [r["id"] for r in whole[key]] == [r["id"] for r in rows] and whole["count"] == 38


# ---- PRD-21124: recommended actions, one record per event type --------------------------------------------


def _recommendations(n=120):
    return {f"type.{i:03d}": {"title": f"Action {i}", "recommendation": "Do this. " * 40} for i in range(n)}


async def test_recommended_actions_walk_every_event_type(monkeypatch):
    rec = Recorder({"reports/alert-recommended-actions": _recommendations()})
    seen, offset, cut, calls = [], None, 0, 0
    while True:
        out = await _call(monkeypatch, rec, "saas_alerts_recommended_actions", {} if offset is None else {"offset": offset})
        calls += 1
        assert "Result too large" not in json.dumps(out) and "retry_page_size" not in out
        cut += bool(out.get("truncated") or out.get("fields_truncated"))
        seen += [r["event_type"] for r in out["recommended_actions"]]
        offset = out.get("next_offset")
        if offset is None:
            break
        assert calls < 60
    assert cut > 0 and seen == [f"type.{i:03d}" for i in range(120)]
    # A full list may shorten long texts to fit; one event type (or a small limit) comes back in full.
    one = await _call(monkeypatch, rec, "saas_alerts_recommended_actions", {"event_type": "type.042"})
    assert one["recommended_actions"][0]["recommendation"] == "Do this. " * 40
    few = await _call(monkeypatch, rec, "saas_alerts_recommended_actions", {"offset": 40, "limit": 10})
    assert all(r["recommendation"] == "Do this. " * 40 for r in few["recommended_actions"])


async def test_recommended_action_for_one_event_type(monkeypatch):
    rec = Recorder({"reports/alert-recommended-actions": _recommendations()})
    out = await _call(monkeypatch, rec, "saas_alerts_recommended_actions", {"event_type": "TYPE.007"})
    assert [r["event_type"] for r in out["recommended_actions"]] == ["type.007"]
    assert out["recommended_actions"][0]["title"] == "Action 7"
    none = await _call(monkeypatch, rec, "saas_alerts_recommended_actions", {"event_type": "no.such.type"})
    assert (none["recommended_actions"], none["total"]) == ([], 0)


async def test_recommended_actions_as_a_list_keep_their_type(monkeypatch):
    rec = Recorder({"reports/alert-recommended-actions": [{"jointType": "login.failure", "action": "Reset"}]})
    out = await _call(monkeypatch, rec, "saas_alerts_recommended_actions", {"event_type": "login.failure"})
    assert out["recommended_actions"] == [{"event_type": "login.failure", "jointType": "login.failure", "action": "Reset"}]


# ---- PRD-21125: events_query says whether more exist and where to continue ---------------------------------


def _events_api(rows):
    def reply(request):
        start = int(request.url.params.get("from", 0))
        size = int(request.url.params.get("size", 50))
        return httpx.Response(200, json=rows[start : start + size])

    return reply


async def test_events_query_reports_has_more_and_next_from(monkeypatch):
    rows = [{"time": f"2026-10-21T00:{i // 60:02d}:{i % 60:02d}Z", "jointType": "login.success", "eventId": f"e{i}"} for i in range(12)]
    rec = Recorder({"reports/events": _events_api(rows)})
    full = await _call(monkeypatch, rec, "saas_alerts_events_query", {"size": 5})
    assert (full["count"], full["has_more"], full["next_from"]) == (5, True, 5)
    last = await _call(monkeypatch, rec, "saas_alerts_events_query", {"size": 5, "from": 10})
    assert (last["count"], last["has_more"], last.get("next_from")) == (2, False, None)


@pytest.mark.parametrize("verbose", [False, True])
async def test_cut_event_pages_continue_from_next_from(monkeypatch, verbose):
    rows = [{"eventId": f"e{i:04d}", "time": "2026-10-21T00:00:00Z", "jointType": "x",
             "jointDesc": "d" * 300, **{f"field{k}": f"value {k}" for k in range(30)}} for i in range(450)]
    rec = Recorder({"reports/events": _events_api(rows)})
    ids, start, cut, calls = [], None, 0, 0
    while True:
        args = {"size": 200, "verbose": verbose} | ({} if start is None else {"from": start})
        out = await _call(monkeypatch, rec, "saas_alerts_events_query", args)
        calls += 1
        assert "retry_page_size" not in out
        cut += bool(out.get("truncated"))
        ids += [e["eventId"] for e in out["events"]]
        start = out.get("next_from")
        if start is None:
            break
        assert calls < 100
    assert cut > 0 and ids == [r["eventId"] for r in rows]


# ---- Elasticsearch / scroll: cut hits drop _scroll_id -------------------------------------------------------


def _es_reply(n, scroll="scroll-1"):
    hits = [{"_id": f"h{i}", "_source": {"eventId": f"h{i}", "time": "2026-10-21T00:00:00Z", "jointType": "x",
                                         **{f"field{k}": f"value {k}" for k in range(40)}}} for i in range(n)]
    return {"_scroll_id": scroll, "took": 3, "hits": {"total": {"value": 5000}, "hits": hits}}


@pytest.mark.parametrize(
    "tool,route,args",
    [
        ("saas_alerts_events_query_advanced", "POST reports/events/query", {"query": {"query": {"match_all": {}}}, "verbose": True}),
        ("saas_alerts_events_scroll", "POST reports/events/scroll", {"scroll_id": "scroll-0", "verbose": True}),
    ],
)
async def test_cut_es_hits_drop_the_scroll_id(monkeypatch, tool, route, args):
    rec = Recorder({route: _es_reply(300)})
    out = await _call(monkeypatch, rec, tool, args)
    assert out["truncated"] is True and 0 < len(out["hits"]["hits"]) < 300 and out["original_count"] == 300
    assert "_scroll_id" not in out and "smaller size" in out["note"]
    assert len(json.dumps(out, separators=(",", ":"))) <= 20_000
    small = Recorder({route: _es_reply(3)})
    whole = await _call(monkeypatch, small, tool, args)
    assert whole["_scroll_id"] == "scroll-1" and len(whole["hits"]["hits"]) == 3 and "truncated" not in whole


async def test_recommended_actions_too_many_to_fit_continue_by_next_offset(monkeypatch):
    rec = Recorder({"reports/alert-recommended-actions": _recommendations(800)})
    seen, offset, cut, calls = [], None, 0, 0
    while True:
        out = await _call(monkeypatch, rec, "saas_alerts_recommended_actions", {} if offset is None else {"offset": offset})
        calls += 1
        cut += bool(out.get("truncated"))
        seen += [r["event_type"] for r in out["recommended_actions"]]
        offset = out.get("next_offset")
        if offset is None:
            break
        assert calls < 100
    assert cut > 0 and seen == [f"type.{i:03d}" for i in range(800)]



# ---- PRD-21121: one organization id ------------------------------------------------------------------------
# Live check: one id as a plain query value gets 422 ("organizationIds" must be an array); the same id twice
# returns that organization's devices with no duplicates (353 + 319 = 672 for two organizations).

@pytest.mark.parametrize(
    "tool,path",
    [
        ("saas_alerts_devices_list_mapped", "reports/unify-mapped-devices-by-account"),
        ("saas_alerts_devices_list_unmapped", "reports/unify-unmapped-devices-by-account"),
        ("saas_alerts_devices_list_ignored", "reports/unify-ignored-devices"),
    ],
)
async def test_one_organization_id_is_sent_as_an_array(monkeypatch, tool, path):
    rec = Recorder({path: [{"_id": "d1"}]})
    await _call(monkeypatch, rec, tool, {"organization_ids": ["tfDpgZTTv3XFsqJF1Tmc"]})
    assert rec.requests[-1].url.params.get_list("organizationIds") == ["tfDpgZTTv3XFsqJF1Tmc"] * 2
    await _call(monkeypatch, rec, tool, {"organization_ids": ["a", "b"]})
    assert rec.requests[-1].url.params.get_list("organizationIds") == ["a", "b"]


# ---- PRD-21122: time_sort and several event types go through the Elasticsearch search ---------------------
# Live checks: GET ignores timeSort and rejects several eventType values (422); the search sorts with
# "sort": [{"time": "desc"}] and its filters match events_count (critical 23, login.success 3,558,
# customer 6,032, user 41).

def _es_hits(rows, total=None):
    return {"hits": {"total": {"value": len(rows) if total is None else total, "relation": "eq"},
                     "hits": [{"_id": r["eventId"], "_source": r} for r in rows]}}


async def test_time_sort_uses_the_search_with_the_same_filters(monkeypatch):
    rec = Recorder({"POST reports/events/query": _es_hits([EVENT | {"eventId": "e1"}], total=40)})
    args = {"customer_id": "c1", "alert_status": "critical", "event_type": ["login.failure"], "user_email": "u@example.com",
            "start_date": "2026-10-21T00:00:00Z", "end_date": "2026-10-22T00:00:00Z", "from": 10, "size": 5, "time_sort": "desc"}
    result = await _call(monkeypatch, rec, "saas_alerts_events_query", args)
    sent = body(rec.requests[0])["body"]
    assert sent["sort"] == [{"time": "desc"}] and (sent["from"], sent["size"]) == (10, 5)
    assert sent["query"] == {"bool": {"filter": [
        {"term": {"customer.id": "c1"}},
        {"term": {"alertStatus": "critical"}},
        {"terms": {"jointType": ["login.failure"]}},
        {"term": {"user.name": "u@example.com"}},
        {"range": {"time": {"gte": "2026-10-21T00:00:00.000Z", "lte": "2026-10-22T00:00:00.000Z"}}},
    ]}}
    assert not rec.calls("GET", "reports/events")
    assert (result["total"], result["count"], result["has_more"], result["next_from"]) == (40, 1, True, 11)


async def test_several_event_types_use_the_search_without_a_sort(monkeypatch):
    rec = Recorder({"POST reports/events/query": _es_hits([EVENT | {"eventId": "e1"}])})
    await _call(monkeypatch, rec, "saas_alerts_events_query", {"event_type": ["login.success", "login.failure"]})
    sent = body(rec.requests[0])["body"]
    assert "sort" not in sent and sent["query"] == {"bool": {"filter": [{"terms": {"jointType": ["login.success", "login.failure"]}}]}}


async def test_time_sort_without_filters_matches_everything(monkeypatch):
    rec = Recorder({"POST reports/events/query": _es_hits([])})
    result = await _call(monkeypatch, rec, "saas_alerts_events_query", {"time_sort": "asc"})
    assert body(rec.requests[0])["body"]["query"] == {"match_all": {}}
    assert (result["count"], result["has_more"], result["total"]) == (0, False, 0)


async def test_sorted_pages_cut_to_fit_continue_from_next_from(monkeypatch):
    rows = [{"eventId": f"e{i:04d}", "time": "2026-10-21T00:00:00Z", "jointType": "x", "jointDesc": "d" * 300,
             **{f"field{k}": f"value {k}" for k in range(30)}} for i in range(420)]

    def reply(request):
        sent = body(request)["body"]
        return httpx.Response(200, json=_es_hits(rows[sent["from"] : sent["from"] + sent["size"]], total=len(rows)))

    rec = Recorder({"POST reports/events/query": reply})
    ids, start, cut, calls = [], None, 0, 0
    while True:
        args = {"size": 200, "time_sort": "desc", "verbose": True} | ({} if start is None else {"from": start})
        out = await _call(monkeypatch, rec, "saas_alerts_events_query", args)
        calls += 1
        assert "retry_page_size" not in out
        cut += bool(out.get("truncated"))
        ids += [e["eventId"] for e in out["events"]]
        start = out.get("next_from")
        if start is None:
            break
        assert calls < 100
    assert cut > 0 and ids == [r["eventId"] for r in rows]


async def test_count_with_several_types_uses_the_search_count(monkeypatch):
    rec = Recorder({"POST reports/events/count/query": {"count": 16677, "_shards": {"total": 1}},
                    "reports/events/count": {"total": 3558}})
    several = await _call(monkeypatch, rec, "saas_alerts_events_count", {"event_type": ["login.success", "login.failure"]})
    assert several == {"total": 16677}
    assert body(rec.requests[0])["body"]["query"] == {"bool": {"filter": [{"terms": {"jointType": ["login.success", "login.failure"]}}]}}
    one = await _call(monkeypatch, rec, "saas_alerts_events_count", {"event_type": ["login.success"]})
    assert one == {"total": 3558} and rec.requests[-1].url.params.get_list("eventType") == ["login.success"]
