# Maintaining this fork

This is the Datum downstream fork of
[`united-security-providers/coraza-envoy-go-filter`](https://github.com/united-security-providers/coraza-envoy-go-filter).
It carries value-add that is not upstream and ships as the WAF filter on the
Datum edge. Read this before rebasing onto a newer upstream release — several
constraints are invisible in a green build and only surface as broken traffic
in production.

## What is datum-specific

- Per-host config overrides, a WAF instance cache, CEL metadata extraction, and
  OpenTelemetry tracing/metrics (`internal/config/{cache,cache_metrics,metadata_extractor}.go`,
  `internal/telemetry/`, and the cache/span wiring in `internal/filter/filter.go`).
- The multi-arch payload `Dockerfile` (busybox base, `.so`-only image) consumed
  by the edge init-container, plus `Dockerfile.dev` for the test harness.
- The response-body-phase block-delivery behaviour in `EncodeData`
  (`StopAndBufferWatermark` hold; no zero-fill `buffer.Set` on the local-reply
  path). See the CHANGELOG entry and `tests/repro/response-body-block/`.

## Landmines when rebasing onto a newer upstream

Each of these compiles and passes an inattentive review, and each breaks the
edge at runtime if you take the upstream version blindly.

1. **Config contract is embedded JSON strings, not YAML maps.** Upstream v2.0.0
   made `directives` and `host_directive_map` native YAML maps (breaking, USP
   PR#106). The Datum network-services-operator extension server emits them as
   JSON strings (`sanitizeJSONPath(...)` in
   `trafficprotectionpolicy_controller.go`). Keep the JSON-string parser in
   `internal/config/config.go` (`json.UnmarshalFromString`, exported
   `Directives`) and the JSON-string `Merge`. Ground truth is what NSO emits —
   grep the *consumer*, not this repo.

2. **CRS include aliases need back-compat entries.** Upstream renamed the
   `internal/config/fs.go` aliases (`@recommended-conf` → `@coraza-setup`,
   `@crs-setup-conf` → `@crs-setup`) and moved the embed from `rules/` to
   `coreruleset/`. NSO still emits `Include @recommended-conf` /
   `Include @crs-setup-conf` / `Include @owasp_crs/*.conf`. Keep back-compat
   alias entries mapping the old names onto `coraza.conf` / `crs-setup.conf`, or
   the WAF loads but fails to resolve includes.

3. **Envoy module is pinned to the edge proxy version, not latest.** The `.so`
   is `dlopen`'d in-process by Envoy; `github.com/envoyproxy/envoy` in `go.mod`
   must match the Envoy version running on the edge (currently `v1.37.1`), not
   whatever upstream bumped to. A mismatch is a runtime ABI failure, invisible
   at build time.

4. **Rebase the source; keep the datum build/test harness.** Take upstream's
   `internal/`, `coreruleset/`, and `go.mod` source. Keep this fork's
   `Makefile`, `.github/workflows/`, `tests/e2e`, `tests/ftw`, `example/`, and
   `Dockerfile*`. Upstream's harness + this fork's Makefile fails FTW on Envoy
   startup (`Timeout waiting for response from http://envoy:8090`).

## Recipe

Do not replay the fork commits across the upstream divergence. Branch off the
target upstream tag and 3-way-apply the net downstream diff:

```
git fetch upstream --tags
git checkout -b datum-<version> <upstream-tag>
git diff <merge-base> origin/<trunk> | git apply --3way
# resolve conflicts per the landmines above, then overlay the harness:
git checkout origin/<trunk> -- Makefile .github/workflows tests/e2e tests/ftw example Dockerfile.dev
```

`<merge-base> = git merge-base origin/<trunk> upstream/main`. The net diff is in
the modern `internal/` layout, so there is no `src/` noise. Expect real
conflicts only in `internal/config/{config,fs}.go` and
`internal/filter/filter.go`.

## Prove it before shipping

A green build and CI do not catch the landmines above (they are all
runtime/config-contract issues). Run the full-stack repro in
`tests/repro/response-body-block/` on an **edge-parity Envoy 1.37.1** stack and
confirm: benign → `200`, inbound SQLi → `403`, response-body leak → `403` with a
non-empty branded body. Then stage → soak → prod, one change at a time.
