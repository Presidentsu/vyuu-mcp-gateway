"""SCIM 2.0 server (RFC 7644 + RFC 7643).

Inbound endpoints under `/scim/v2/{directory_id}/...` that the IdP
calls into to provision / deprovision Users + Groups. Bearer-token
auth against `idp_directories.scim_token_hash`. Tenant scoping is
derived from the directory after the bearer check succeeds.

We hand-roll the spec rather than pull a third-party SCIM library —
the surface is small (Users + Groups + a few discovery endpoints),
and the provider quirks (Entra `Operations[]` PATCH, Workspace
`members[]` replace) are easier to bake in directly than to fight a
library's normalization layer.
"""
