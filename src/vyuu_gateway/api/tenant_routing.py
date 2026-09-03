"""IDP-3 · resolve a tenant from the request's `Host` header.

`acme.gateway.example.com` should land Acme's users on Acme's login page
without anyone pasting a UUID. This module turns the `Host` header into a
slug, and the slug into a tenant.

## A routing hint, never an authorization input

`Host` is client-supplied. Unless the reverse proxy pins it, an attacker
can send any value they like — so resolving a tenant from it grants
**nothing**. It selects which login page to render. Authentication runs
unchanged afterwards, and the session token that comes out carries the
tenant it was actually minted for.

The worst a forged `Host` achieves is showing someone the wrong login
form. Keep it that way: if a future change reads the resolved tenant for
an access decision, that property is gone and this becomes a
tenant-confusion vulnerability.

## Reserved labels

A tenant must not be able to claim `www`, `api`, `admin` or friends — not
because it would breach isolation, but because it would shadow a hostname
the deployment needs for something else, and the failure would look like
a DNS problem rather than a naming collision.
"""

from __future__ import annotations

import re
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import Tenant

# Mirrors the DB CHECK constraint in migration 20260825_0021. Duplicated
# on purpose: the DB is the backstop that no writer can bypass, this one
# gives a useful error before the round-trip.
SLUG_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Labels a tenant may not claim. Not a security boundary — a shadowed
# `api.` subdomain is an operational outage, not a breach — but the
# failure mode is confusing enough to be worth refusing up front.
RESERVED_SLUGS: frozenset[str] = frozenset(
    {
        "www", "api", "admin", "app", "portal", "operator", "gateway",
        "auth", "login", "sso", "scim", "mcp", "static", "assets",
        "docs", "status", "health", "metrics", "mail", "smtp", "ftp",
        "ns", "ns1", "ns2", "cdn", "test", "staging", "dev", "internal",
        "localhost",
    }
)


class InvalidTenantSlugError(ValueError):
    """Slug is malformed, reserved, or already taken."""


def normalize_slug(raw: str) -> str:
    """Lower-case, strip, and validate. Raises `InvalidTenantSlugError`.

    Deliberately does NOT slugify (replacing spaces/underscores, stripping
    accents): a silently-transformed slug is a hostname the operator did
    not choose and will not predict. Reject and let them retype.
    """

    slug = (raw or "").strip().lower()
    if not slug:
        raise InvalidTenantSlugError("slug must not be empty")
    if len(slug) < 2:
        raise InvalidTenantSlugError("slug must be at least 2 characters")
    if len(slug) > 63:
        raise InvalidTenantSlugError("slug must be at most 63 characters (DNS label limit)")
    if not SLUG_PATTERN.match(slug):
        raise InvalidTenantSlugError(
            "slug must be lowercase letters, digits and inner hyphens only "
            "— it becomes a DNS label"
        )
    if slug in RESERVED_SLUGS:
        raise InvalidTenantSlugError(f"{slug!r} is reserved for platform use")
    return slug


def slug_from_host(host: str | None, *, base_domain: str | None) -> str | None:
    """Extract the tenant slug from a `Host` header.

    Returns None when there is no base domain configured, when the host
    is not under it, or when the label left over is empty or reserved.
    `acme.gateway.example.com` under base `gateway.example.com` → `acme`.

    Only a SINGLE label is accepted: `a.b.gateway.example.com` returns
    None rather than `a.b`. Multi-label would need a wildcard cert per
    depth, and more importantly `a.b` is not a slug any tenant can hold —
    silently accepting it would make the "which tenant is this?" answer
    depend on how many dots the caller typed.
    """

    if not host or not base_domain:
        return None
    # Strip the port; IPv6 literals arrive bracketed and never match a
    # base domain, so they fall out below.
    hostname = host.split(":", 1)[0].strip().lower().rstrip(".")
    base = base_domain.strip().lower().rstrip(".")
    if not hostname or not base or not hostname.endswith("." + base):
        return None
    label = hostname[: -(len(base) + 1)]
    if not label or "." in label or label in RESERVED_SLUGS:
        return None
    if not SLUG_PATTERN.match(label):
        return None
    return label


def tenant_from_host(
    session: Session, *, host: str | None, base_domain: str | None
) -> Tenant | None:
    """Resolve the `Host` header to a tenant row, or None.

    Untenanted read of `tenants`, which carries no RLS — the same access
    the existing `/default-tenant` endpoint already relies on.
    """

    slug = slug_from_host(host, base_domain=base_domain)
    if slug is None:
        return None
    return session.scalar(select(Tenant).where(Tenant.slug == slug))


def set_tenant_slug(
    session: Session, *, tenant_id: UUID, slug: str | None
) -> Tenant:
    """Assign (or clear) a tenant's slug. Does not commit.

    Uniqueness is enforced by the DB index; this pre-checks so the caller
    gets `InvalidTenantSlugError` rather than an opaque IntegrityError,
    and so a collision does not poison the caller's transaction.
    """

    tenant = session.get(Tenant, tenant_id)
    if tenant is None:
        raise InvalidTenantSlugError("tenant not found")
    if slug is None:
        tenant.slug = None
        return tenant

    normalized = normalize_slug(slug)
    taken = session.scalar(
        select(Tenant).where(Tenant.slug == normalized, Tenant.id != tenant_id)
    )
    if taken is not None:
        raise InvalidTenantSlugError(f"{normalized!r} is already in use")
    tenant.slug = normalized
    return tenant
