# TLS termination + mTLS — operational guide (H2)

This document covers two responsibilities the gateway **does not own
itself** but every production deployment must address:

1. **TLS termination at ingress** — the gateway speaks HTTP internally;
   production runs MUST terminate TLS in front.
2. **mTLS to upstream MCPs** — for regulated tenants that require
   client-cert auth on outbound traffic.

The gateway already speaks HTTPS via `httpx` for outbound calls (token
URLs, JWKS, manifest fetches all require `https://`). What's missing is
operational guidance for the inbound side and the upstream-mTLS knob.

## 1. Inbound TLS termination

### Why not in the gateway

Pure-Python TLS termination on the request hot path is slower, harder
to tune (cert rotation, OCSP stapling, ALPN), and duplicates what every
production environment already runs in front of an HTTP service. The
gateway exposes plain HTTP and assumes a TLS-terminating proxy or
ingress controller sits in front.

### Reference deployments

#### Kubernetes (most common)

NGINX ingress with a cert-manager-issued cert:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vyuu-gateway
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/backend-protocol: HTTP
spec:
  ingressClassName: nginx
  tls:
    - hosts: [gateway.vyuu.example]
      secretName: vyuu-gateway-tls
  rules:
    - host: gateway.vyuu.example
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: vyuu-gateway
                port: { number: 8000 }
```

Gateway pods listen on `:8000` plaintext inside the cluster; the
ingress fronts them with TLS 1.3 + auto-renewing certs.

#### Plain VM / systemd

Caddy is the lowest-friction option (auto-renews via ACME):

```
gateway.vyuu.example {
    reverse_proxy 127.0.0.1:8000
    encode gzip
    log
}
```

#### Cloud-native LBs

- **AWS ALB / NLB** with ACM-issued cert, target group → gateway pods
  on port 8000 (HTTP backend).
- **GCP Cloud Run** terminates TLS automatically; deploy the gateway
  as a Cloud Run service, no ingress to configure.
- **Azure App Service** likewise terminates TLS at the platform edge.

### TLS version + cipher policy

The gateway has no opinion. Configure at the ingress:

- Minimum TLS 1.2; prefer TLS 1.3.
- Enable HSTS with `Strict-Transport-Security: max-age=31536000;
  includeSubDomains; preload` once the cert is stable.
- Disable plain HTTP entirely or 301-redirect to HTTPS.

### Client → ingress mTLS (if required)

For tenants that mandate client-cert auth on inbound traffic, configure
mTLS at the ingress and propagate the verified subject to the gateway
via a header (e.g. NGINX `ssl_client_s_dn`). The gateway's
`ApiKeyIdentityProvider` already gates on bearer; add a small
`MtlsIdentityProvider` if subject-DN-based identity is needed (~½ day,
extends the existing `IdentityProvider` Protocol).

## 2. Outbound mTLS to upstream MCPs

For regulated verticals (BFSI, healthcare) some upstream MCPs require
the gateway to present a client certificate.

### What works today

`StreamableHttpMcpClient` and `SseMcpClient` build on `httpx.AsyncClient`,
which natively supports client certs via the `cert=` parameter. Wiring
this through the existing `auth_*` config columns is straightforward and
sized as a follow-up:

- Add an `mtls_cert_ref` + `mtls_key_ref` pair to `mcp_servers` (refs
  resolved through the same `SecretStore` that handles `auth_headers`).
- `DatabaseBackedUpstreamClientProvider._build_client` resolves the refs
  to PEM bytes and passes them to `httpx.AsyncClient(cert=...)`.
- Schema validation: cert + key must be paired (one without the other
  is a config error); HTTPS-only on `source_location` (already enforced
  via `validate_http_source_url`).

This isn't shipped yet — the `SecretStore` Protocol is ready (A6),
the upstream-client builder has the seam, but no `mcp_servers` column
or schema rule exists. Sized as ~½ day on top of A6.

### Until then: sidecar-based outbound mTLS

A pragmatic interim: run an **mTLS-terminating egress sidecar** (e.g.
Envoy) next to the gateway pod, and have the gateway send plain HTTP to
the sidecar's listener. Sidecar adds the client cert on the way out.
Same pattern Istio / Linkerd default to. Works today with no gateway
code change.

## 3. Production checklist

Before exposing the gateway to real traffic:

- [ ] Inbound TLS terminated at ingress, min TLS 1.2.
- [ ] HSTS enabled.
- [ ] Plain HTTP disabled or redirected.
- [ ] `VYUU_INBOUND_IDENTITY_PROVIDER=api_key` set (production auth).
- [ ] `VYUU_OPERATOR_AUTH_SIGNING_SECRET` and
      `VYUU_PORTAL_SESSION_SIGNING_SECRET` are long random values, not
      the `dev-*` placeholders.
- [ ] `VYUU_SECRET_STORE_BACKEND=vault` (or another real backend),
      `VYUU_VAULT_ADDR` and `VYUU_VAULT_TOKEN` set.
- [ ] DB connection pool sized for peak inbound concurrency.
- [ ] Audit pipeline (Kafka / NATS) provisioned and reachable; the
      in-memory `RecentAuditEmitter` is for the operator UI dashboard,
      NOT durable audit storage.
- [ ] Upstream MCPs that require mTLS are fronted by an egress sidecar
      (until first-class `mtls_cert_ref` lands).

## 4. References

- TLS at the ingress — your platform's ingress controller docs.
- HSTS — RFC 6797.
- mTLS on httpx — `httpx.AsyncClient(cert=("client.crt", "client.key"))`.
- ACME / Let's Encrypt — cert-manager.io for k8s, Caddy for VMs.
