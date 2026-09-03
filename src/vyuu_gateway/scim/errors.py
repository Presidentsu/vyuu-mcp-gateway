"""RFC 7644 §3.12 error response shape.

Every SCIM error must be a JSON object with the shape:

```
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "404",
  "detail": "Resource not found",
  "scimType": "..."   # optional, RFC 7644 §3.12 enumerates the values
}
```

The IdP relies on `status` + (sometimes) `scimType` to drive its own
retry / dedup logic. Bare 404 / 400 from FastAPI's default handler
won't satisfy Entra/Workspace; that's why we have this module.
"""

from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse


def scim_error(
    *,
    status_code: int,
    detail: str,
    scim_type: str | None = None,
) -> JSONResponse:
    """Build a SCIM error response. `status` is rendered as a string
    per the spec (some IdPs reject numeric statuses)."""

    body: dict[str, Any] = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": str(status_code),
        "detail": detail,
    }
    if scim_type:
        body["scimType"] = scim_type
    return JSONResponse(body, status_code=status_code)


def scim_400(detail: str, scim_type: str = "invalidValue") -> JSONResponse:
    """400 Bad Request. `scimType` defaults to `invalidValue` —
    RFC 7644 §3.12's catch-all for malformed payloads."""

    return scim_error(status_code=400, detail=detail, scim_type=scim_type)


def scim_401(detail: str = "authentication required") -> JSONResponse:
    """401 Unauthorized. We never disclose whether the directory id
    or the bearer was wrong — anti-enumeration."""

    return scim_error(status_code=401, detail=detail)


def scim_404(detail: str = "resource not found") -> JSONResponse:
    return scim_error(status_code=404, detail=detail)


def scim_409(detail: str, scim_type: str = "uniqueness") -> JSONResponse:
    """409 Conflict. `scimType=uniqueness` is the spec value for
    "this attribute violates a uniqueness constraint" — Entra and
    Workspace both retry on this one."""

    return scim_error(status_code=409, detail=detail, scim_type=scim_type)
