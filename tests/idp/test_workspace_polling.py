"""IDP-2 · Google Workspace directory polling.

Workspace custom SAML apps **cannot SCIM-push** — auto-provisioning is
reserved for apps in Google's own catalog. So our SCIM endpoint never
hears from Workspace, and without this a Workspace tenant runs on
JIT-create with *manual* deprovisioning: someone terminated in HR keeps
working access until an operator notices.

The tests that carry the weight are the ones about **not** acting:

- `test_a_failed_listing_deactivates_nobody` — polling has a failure mode
  a push does not. "Absent from the response" and "deleted" are the same
  observation, so a transient API error must never read as a mass
  termination.
- `test_reconcile_refuses_to_deactivate_on_an_incomplete_listing` — the
  same property at the reconciliation layer, where the decision is made.
- `test_users_are_deactivated_never_deleted` — a wrong answer has to stay
  recoverable inside the hard-delete sweeper's grace window.

Google is stubbed via `httpx.MockTransport`; no network, no credentials.
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

import httpx
import pytest

from vyuu_gateway.idp.workspace_polling import (
    PollReport,
    WorkspacePollError,
    WorkspaceUser,
    list_workspace_users,
    parse_workspace_user,
    reconcile,
)

# --- Mapping the Admin SDK resource ------------------------------------------


def test_suspended_and_archived_both_mean_inactive() -> None:
    """Google models them separately — suspended is disabled, archived is
    kept for retention without a licence. For access purposes they are
    the same answer, and treating `archived` as active would leave
    departed staff with working credentials."""

    base = {"id": "1", "primaryEmail": "A@Corp.Example", "name": {"fullName": "A"}}
    assert parse_workspace_user(base).active is True
    assert parse_workspace_user({**base, "suspended": True}).active is False
    assert parse_workspace_user({**base, "archived": True}).active is False


def test_email_is_normalised() -> None:
    user = parse_workspace_user({"id": "1", "primaryEmail": "  A@Corp.Example "})
    assert user is not None
    assert user.email == "a@corp.example"


@pytest.mark.parametrize(
    "raw", [{}, {"id": "1"}, {"primaryEmail": "a@b.c"}, {"id": "", "primaryEmail": ""}]
)
def test_unusable_entries_are_dropped_not_guessed_at(raw: dict) -> None:
    assert parse_workspace_user(raw) is None


def test_scim_shape_round_trip() -> None:
    """Polled and pushed users must be the same object by the time
    anything writes them, so the audit trail cannot tell them apart."""

    scim = WorkspaceUser(
        external_id="42", email="a@corp.example", display_name="A", active=True
    ).to_scim()
    assert scim.userName == "a@corp.example"
    assert scim.externalId == "42"
    assert scim.active is True


# --- Listing: partial reads must fail, not truncate --------------------------


def _http(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_pagination_walks_to_completion() -> None:
    pages = [
        {"users": [{"id": "1", "primaryEmail": "a@x.test"}], "nextPageToken": "t2"},
        {"users": [{"id": "2", "primaryEmail": "b@x.test"}]},
    ]
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        token = request.url.params.get("pageToken")
        seen.append(token)
        return httpx.Response(200, json=pages[0] if token is None else pages[1])

    async def run() -> list[WorkspaceUser]:
        async with _http(handler) as http:
            return await list_workspace_users(
                access_token="t", customer_id="my_customer", http=http
            )

    users = asyncio.run(run())
    assert [u.external_id for u in users] == ["1", "2"]
    assert seen == [None, "t2"]


def test_a_mid_pagination_error_raises_rather_than_truncating() -> None:
    """Returning what we got so far would make the missing page look like
    deleted users."""

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(
                200,
                json={"users": [{"id": "1", "primaryEmail": "a@x.test"}],
                      "nextPageToken": "t2"},
            )
        return httpx.Response(503, text="backend error")

    async def run() -> Any:
        async with _http(handler) as http:
            return await list_workspace_users(
                access_token="t", customer_id="my_customer", http=http
            )

    with pytest.raises(WorkspacePollError, match="503"):
        asyncio.run(run())


def test_network_failure_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns")

    async def run() -> Any:
        async with _http(handler) as http:
            return await list_workspace_users(
                access_token="t", customer_id="c", http=http
            )

    with pytest.raises(WorkspacePollError, match="unreachable"):
        asyncio.run(run())


def test_customer_id_is_always_sent() -> None:
    """Without it, a reseller service account enumerates other
    customers' directories."""

    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.params.get("customer"))
        return httpx.Response(200, json={"users": []})

    async def run() -> Any:
        async with _http(handler) as http:
            return await list_workspace_users(
                access_token="t", customer_id="C03xyz", http=http
            )

    asyncio.run(run())
    assert seen == ["C03xyz"]


def test_runaway_pagination_is_bounded() -> None:
    """An unbounded loop in a background task is worse than a loud
    failure telling the operator they need incremental sync."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"users": [], "nextPageToken": "always-more"}
        )

    async def run() -> Any:
        async with _http(handler) as http:
            return await list_workspace_users(
                access_token="t", customer_id="c", http=http
            )

    with pytest.raises(WorkspacePollError, match="incremental sync"):
        asyncio.run(run())


# --- Reconciliation ----------------------------------------------------------


class _FakeUser:
    def __init__(self, external_id: str, disabled: bool = False) -> None:
        self.external_id = external_id
        self.email = f"{external_id}@x.test"
        self.disabled_at = object() if disabled else None
        self.soft_deleted_at = None


class _FakeSession:
    """Just enough Session for `reconcile`: it only ever runs one
    `select(User)`."""

    def __init__(self, users: list[_FakeUser]) -> None:
        self._users = users

    def scalars(self, statement: Any) -> Any:
        users = self._users

        class _R:
            def all(self) -> list[_FakeUser]:
                return users

        return _R()


class _FakeDirectory:
    tenant_id = uuid4()
    id = uuid4()
    display_name = "Acme · Workspace"


def _reconcile(
    remote: list[WorkspaceUser],
    local: list[_FakeUser],
    *,
    complete: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[PollReport, list[tuple[str, bool]]]:
    """Runs reconcile with the SCIM service functions stubbed, so the
    assertions are about *decisions* rather than about persistence —
    which `tests/scim/` already covers."""

    from vyuu_gateway.idp import workspace_polling

    calls: list[tuple[str, bool]] = []

    def fake_set_active(db: Any, *, directory: Any, user: Any, active: bool) -> None:
        calls.append((user.external_id, active))

    def fake_create(db: Any, *, directory: Any, payload: Any) -> Any:
        calls.append((payload.externalId, True))
        return object()

    monkeypatch.setattr(workspace_polling.scim_users, "set_active", fake_set_active)
    monkeypatch.setattr(workspace_polling.scim_users, "create_from_scim", fake_create)

    report = PollReport()
    reconcile(
        _FakeSession(local),  # type: ignore[arg-type]
        directory=_FakeDirectory(),  # type: ignore[arg-type]
        workspace_users=remote,
        listing_complete=complete,
        report=report,
    )
    return report, calls


def _remote(external_id: str, active: bool = True) -> WorkspaceUser:
    return WorkspaceUser(
        external_id=external_id,
        email=f"{external_id}@x.test",
        display_name=None,
        active=active,
    )


def test_new_active_user_is_provisioned(monkeypatch: pytest.MonkeyPatch) -> None:
    report, calls = _reconcile([_remote("1")], [], complete=True, monkeypatch=monkeypatch)
    assert report.created == 1
    assert calls == [("1", True)]


def test_new_but_already_inactive_user_is_not_provisioned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Creating a row just to deactivate it would manufacture two audit
    rows for a non-event."""

    report, calls = _reconcile(
        [_remote("1", active=False)], [], complete=True, monkeypatch=monkeypatch
    )
    assert report.created == 0
    assert calls == []


def test_suspended_user_is_deactivated(monkeypatch: pytest.MonkeyPatch) -> None:
    report, calls = _reconcile(
        [_remote("1", active=False)], [_FakeUser("1")], complete=True, monkeypatch=monkeypatch
    )
    assert report.deactivated == 1
    assert calls == [("1", False)]


def test_unsuspended_user_is_reactivated(monkeypatch: pytest.MonkeyPatch) -> None:
    report, calls = _reconcile(
        [_remote("1")], [_FakeUser("1", disabled=True)], complete=True, monkeypatch=monkeypatch
    )
    assert report.reactivated == 1
    assert calls == [("1", True)]


def test_unchanged_users_produce_no_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    """A five-minute poll over a stable directory must not churn the
    audit log."""

    report, calls = _reconcile(
        [_remote("1")], [_FakeUser("1")], complete=True, monkeypatch=monkeypatch
    )
    assert report.changed == 0
    assert calls == []


def test_user_absent_from_a_complete_listing_is_deactivated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, calls = _reconcile([], [_FakeUser("1")], complete=True, monkeypatch=monkeypatch)
    assert report.deactivated == 1
    assert calls == [("1", False)]


def test_reconcile_refuses_to_deactivate_on_an_incomplete_listing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The load-bearing safety property. "Absent from the response" and
    "deleted" are the same observation, so absence is only meaningful
    when we know we saw everything."""

    report, calls = _reconcile([], [_FakeUser("1")], complete=False, monkeypatch=monkeypatch)
    assert report.deactivated == 0
    assert calls == []


def test_creates_still_apply_on_an_incomplete_listing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partial read cannot cause a wrong *creation* — the user was
    observed. Only deletion-by-absence is unsafe."""

    report, _calls = _reconcile(
        [_remote("2")], [_FakeUser("1")], complete=False, monkeypatch=monkeypatch
    )
    assert report.created == 1
    assert report.deactivated == 0


def test_a_jit_race_on_create_is_absorbed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A user signing in for the first time while a poll is running
    creates the same row. The sign-in path wins; the poll must not
    explode."""

    from vyuu_gateway.idp import workspace_polling

    def raises(db: Any, *, directory: Any, payload: Any) -> Any:
        raise workspace_polling.scim_users.ScimUserExistsError

    monkeypatch.setattr(workspace_polling.scim_users, "create_from_scim", raises)
    monkeypatch.setattr(
        workspace_polling.scim_users, "set_active", lambda *a, **k: None
    )
    report = PollReport()
    reconcile(
        _FakeSession([]),  # type: ignore[arg-type]
        directory=_FakeDirectory(),  # type: ignore[arg-type]
        workspace_users=[_remote("1")],
        listing_complete=True,
        report=report,
    )
    assert report.created == 0


def test_users_are_deactivated_never_deleted(monkeypatch: pytest.MonkeyPatch) -> None:
    """The poller has no hard-delete path at all — the existing sweeper's
    7-day grace is what makes a wrong answer recoverable."""

    import inspect

    from vyuu_gateway.idp import workspace_polling

    source = inspect.getsource(workspace_polling)
    assert "hard_delete" not in source, (
        "the poller must not hard-delete: a partial read would become "
        "irreversible data loss"
    )
