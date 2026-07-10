# Response-body-phase block delivery repro (infra#3324)

Reproduces the bug this PR fixes: a `TrafficProtectionPolicy` in `Enforce` mode
that blocks on the **response body** did not deliver the block to the client —
small responses were served through with the origin `200` (silent WAF bypass),
large ones were reset mid-stream (`transfer closed`). Root cause: the filter
committed the upstream `200` response headers (via `api.Continue` on non-final
`EncodeData` chunks) before the response-body verdict, after which an encode-path
`SendLocalReply` cannot replace them (envoyproxy/envoy#39775).

This is a full-stack (NSO downstream gateway + extension-server) repro because the
symptom is Envoy-version-specific: it only manifests on Envoy **`contrib-v1.37.1`**
(edge/prod). The filter `.so` is amd64-only and is `dlopen`'d in-process, so on
Apple Silicon the Envoy image must be the amd64 build (pinned by digest) run under
Rosetta. Full recipe: see the `waf-local-repro-stack` note.

## Prereqs
- kind cluster with cert-manager, Envoy Gateway (+ CRDs), the NSO downstream EG
  (`config/tools/envoy-gateway-downstream`, extensionManager → extension-server),
  and the extension-server (`config/dev/extension-server-local`) with
  `SecResponseBodyAccess On` and `SecResponseBodyLimit <= per_connection_buffer_limit_bytes`.
- The coraza `.so` under test loaded into the gateway (`downstream-gateway.local.yaml`,
  set the `coraza-waf` image tag).

## Apply
```
kubectl apply -f pki.yaml
kubectl apply -f downstream-gateway.local.yaml
kubectl apply -f demo-outbound.yaml
```

## Drive (via port-forward — NOT the kind nodePort)
```
kubectl -n datum-downstream-gateway port-forward svc/envoy-datum-downstream-gateway-<hash> 18080:80 &

# response body trips a phase-4 outbound CRS rule (959100); TPP outbound threshold lowered
curl -sS -D- -H 'Host: demo.local' http://localhost:18080/
```

## Expected (fixed)
| case | before | after |
|---|---|---|
| small blocked response body | `200` origin body (bypass) | `403 Request blocked by security policy.` |
| large blocked response body (in inspection window) | `transfer closed` | `403 Request blocked by security policy.` |
| large **benign** response (> buffer) | — | `200` streamed (no `payload_too_large`) |
| benign | `200` | `200` |
| inbound SQLi | `403` | `403` |
