"""F-AUZ-005 - cross-tenant SEARCH isolation (D-P0-003 testing requirement 5). Search is PostgreSQL full-text search over the tenant's own evidence
metadata, executed by the application role under FORCE'd row-level security: results, snippets and counts can only come from the caller's tenant,
the query language cannot widen the tenant filter, Restricted hits are re-authorised per item, and the query text is never written to the audit trail."""
from urllib.parse import quote

import pytest
from django.conf import settings

from ngrc.evidence.views import _SEARCH_SQL

from .conftest import role_connect
from .evidence_factory import create, make_evidence
from .helpers import Api, audit_events

pytestmark = pytest.mark.security


def search(user, q, **kw):
    return user.api.get(f"/tenant/search/?q={quote(q, safe='')}", **kw)


def ids(resp) -> set[str]:
    return {h["id"] for h in resp.json()["results"]}


def test_results_come_only_from_the_callers_tenant(tenant_a, tenant_b, make_user):
    a, b = make_user(tenant_a, "owner"), make_user(tenant_b, "owner")
    da = make_evidence(a, title="Quarterly review ZEBRA alpha", description="visible to tenant A only")
    db = make_evidence(b, title="Quarterly review ZEBRA beta", description="visible to tenant B only")
    ra, rb = search(a, "zebra"), search(b, "zebra")
    assert ids(ra) == {da.id} and ids(rb) == {db.id}
    assert "beta" not in ra.content.decode() and "tenant B" not in ra.content.decode()          # not in titles, snippets or anywhere else
    assert "alpha" not in rb.content.decode() and ra.json()["count"] == rb.json()["count"] == 1  # counts reveal nothing about the other tenant


def test_a_term_that_exists_only_in_another_tenant_finds_nothing_and_looks_like_any_empty_search(tenant_a, tenant_b, make_user):
    a, b = make_user(tenant_a, "owner"), make_user(tenant_b, "owner")
    make_evidence(b, title="Confidential merger plan MARMALADE")
    foreign, nothing = search(a, "marmalade"), search(a, "qzxjvwk")
    assert foreign.status_code == nothing.status_code == 200 and foreign.json() == nothing.json() == {"results": [], "count": 0}


def test_search_needs_authentication_a_tenant_context_and_the_permission(tenant_a, make_user):
    assert Api().get("/tenant/search/?q=x").status_code == 401
    assert make_user(tenant_a, "owner", select_tenant=False).api.get("/tenant/search/?q=x").status_code == 403
    assert search(make_user(tenant_a, "member"), "review").status_code == 403                    # the default member role has no evidence.read
    assert audit_events(tenant_id=tenant_a.id, action="authz.denied", reason_code="permission_missing")


def test_restricted_hits_are_reauthorised_per_item(tenant_a, make_user):
    owner, admin = make_user(tenant_a, "owner"), make_user(tenant_a, "admin")
    pub = make_evidence(owner, title="Board paper PUBLICSUMMARY")
    sec = make_evidence(owner, title="Board paper PRIVATEMINUTES", data_class="R")
    assert ids(search(owner, "board")) == {pub.id, sec.id}                                       # the privileged reader sees both
    assert ids(search(admin, "board")) == {pub.id}                                               # a stale index entry would not widen access
    assert "PRIVATEMINUTES" not in search(admin, "board paper").content.decode() and search(admin, "privateminutes").json()["count"] == 0


@pytest.mark.parametrize("q", ["' OR 1=1 --", "tenant_id:*", "*", "{{7*7}}", "a | b", "!zebra", "zebra:*", "\"quoted phrase\"", "tenant_id = tenant_id",
                               "'; DROP TABLE ten_evidence; --", "<script>alert(1)</script>", "x" * 200, "‮\u0000"[:1]])
def test_query_syntax_cannot_widen_the_tenant_filter_or_break_the_server(q, tenant_a, tenant_b, make_user):
    a, b = make_user(tenant_a, "owner"), make_user(tenant_b, "owner")
    foreign = make_evidence(b, title="FOREIGNDOC zebra secret", description="other tenant zebra")
    make_evidence(a, title="own zebra document")
    r = search(a, q)
    assert r.status_code in (200, 400), (q, r.status_code)
    assert foreign.id not in r.content.decode() and "FOREIGNDOC" not in r.content.decode()
    assert search(a, "zebra").status_code == 200                                                   # the table is intact


@pytest.mark.parametrize("q", ["", "   ", "x" * 201, "bad\x00byte", "line\nbreak", "tab\there", "\x7f"])
def test_invalid_queries_are_rejected_cleanly(q, tenant_a, make_user):
    a = make_user(tenant_a, "owner")
    r = search(a, q)
    assert r.status_code == 400 and r.json() == {"error": "invalid_query"}


def test_the_query_text_is_never_audited_only_its_length_and_the_result_count(tenant_a, make_user):
    a = make_user(tenant_a, "owner")
    make_evidence(a, title="Findings CANARYTERM987")
    assert search(a, "CANARYTERM987").json()["count"] == 1
    ev = audit_events(tenant_id=tenant_a.id, action="search.executed", actor_id=a.account.id)
    assert ev and "CANARYTERM987" not in ev[-1]["details"] and '"count":1' in ev[-1]["details"].replace(" ", "") and '"query_length":13' in ev[-1]["details"].replace(" ", "")


def test_results_are_capped_and_ranked(tenant_a, make_user):
    a = make_user(tenant_a, "owner")
    for i in range(settings.SEARCH_MAX_RESULTS + 5):
        create(a, title=f"rotation evidence {i}", description="")
    r = search(a, "rotation")
    assert r.json()["count"] == settings.SEARCH_MAX_RESULTS and len(r.json()["results"]) == settings.SEARCH_MAX_RESULTS


def test_snippets_are_plain_text_without_markup(tenant_a, make_user):
    a = make_user(tenant_a, "owner")
    make_evidence(a, title="Plain", description="the <b>bold</b> claim about retention was reviewed")
    hit = search(a, "retention").json()["results"][0]
    assert "[retention]" in hit["snippet"] and "<" not in hit["snippet"] and ">" not in hit["snippet"]   # the headline parser drops markup; matches are marked with [ ]
    assert search(a, "retention")["Content-Type"].startswith("application/json")                         # never rendered as HTML by the API


# ------------------------------------------------------------------------------------------------ the database layer, without the application
def run_search(tenant, term, *, restricted=True):
    with role_connect("ngrc_app") as c:
        if tenant is not None:
            c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant.id)])
        return c.execute(_SEARCH_SQL, [term, restricted, 50]).fetchall()


def test_row_level_security_alone_confines_the_search_sql(tenant_a, tenant_b, make_user):
    a, b = make_user(tenant_a, "owner"), make_user(tenant_b, "owner")
    make_evidence(a, title="RLSPROBE in tenant A")
    mb = make_evidence(b, title="RLSPROBE in tenant B")
    own, other = run_search(tenant_a, "rlsprobe"), run_search(tenant_b, "rlsprobe")
    assert len(own) == len(other) == 1 and str(own[0][0]) != mb.id and str(other[0][0]) == mb.id
    assert run_search(None, "rlsprobe") == []                                                     # no tenant context: fail closed, nothing visible
    for role in ("ngrc_auth", "ngrc_ops"):
        with role_connect(role) as c, pytest.raises(Exception):  # noqa: B017,PT011 - any refusal is the point
            c.execute(_SEARCH_SQL, ["rlsprobe", True, 5])


def test_every_searchable_row_carries_its_tenant_and_the_vector_is_derived_by_the_database(tenant_a, make_user):
    a = make_user(tenant_a, "owner")
    m = make_evidence(a, title="Derived vector", description="generated column check")
    with role_connect("ngrc_owner") as c:
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_a.id)])
        assert c.execute("SELECT count(*) FROM ten_evidence WHERE tenant_id IS NULL").fetchone()[0] == 0
        vec = c.execute("SELECT search_vector::text FROM ten_evidence WHERE id = %s", [m.id]).fetchone()[0]
        assert "'derived'" in vec and "'generated'" in vec
        gen = c.execute("SELECT is_generated FROM information_schema.columns WHERE table_name = 'ten_evidence' AND column_name = 'search_vector'").fetchone()[0]
        assert gen == "ALWAYS"                                                                       # nobody can write a vector that disagrees with the data
    with role_connect("ngrc_app") as c:
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_a.id)])
        with pytest.raises(Exception):  # noqa: B017,PT011
            c.execute("UPDATE ten_evidence SET search_vector = to_tsvector('x') WHERE id = %s", [m.id])
