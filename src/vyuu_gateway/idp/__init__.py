"""IdP directory + SCIM provisioning support.

Two surfaces:

- **`idp.service`** — admin-side CRUD on `idp_directories` rows
  (connect / disconnect Entra ID + Google Workspace).
- **`idp.scim_tokens`** — mint + verify the SCIM bearer that the
  admin pastes into the IdP's "Provisioning" config.

The actual SCIM server (the endpoints the IdP calls into) lives in
`vyuu_gateway.scim` — kept separate so the directory-management
surface and the inbound-protocol surface can evolve independently.
"""
