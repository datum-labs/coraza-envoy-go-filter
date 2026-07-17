# Changelog

## [Unreleased]

### Added
- Add `RELEASING.md` documenting the fork's release process: an own SemVer version line with the upstream base recorded as build metadata (`vX.Y.Z+upstream.<base>`), a clean `vX.Y.Z` image tag plus an `org.opencontainers.image.base.version` label, bump rules, and consumer guidance. Replaces the ad-hoc `-datum.N` pre-release tagging convention.

### Changed
- `release.yml` now derives the OCI image tag from the release git tag by stripping SemVer build metadata, so a `vX.Y.Z+upstream.<base>` tag publishes the image as `vX.Y.Z` (OCI tags cannot contain `+`). The upstream base and standard provenance are stamped as image labels (`org.opencontainers.image.base.version`, `.version`, `.source`, `.revision`).

## [v2.0.2-datum.2] - 2026-07-15

### Added
- Add a `make test` target (`go test ./internal/...`) and run it in the `Testbench` CI job, so in-process Go unit tests execute on every push/PR. Previously CI ran only the docker-based FTW/e2e curl testbenches, leaving unit tests unexecuted. ([datum-cloud/infra#3418](https://github.com/datum-cloud/infra/issues/3418))
- Emit the matched variable, key, and (config-gated) value plus the rule message on the `coraza.rule_violation` and `coraza.interruption` span events, so downstream traces can attribute a block to *what* a rule matched, not just the rule id. The payload-bearing matched value is gated behind `emit_matched_value` (default off) and truncated; the variable name and key are always emitted. ([datum-cloud/infra#3411](https://github.com/datum-cloud/infra/issues/3411))

## [v2.0.2-datum.1] - 2026-07-10

*Datum realign of the downstream fork onto upstream v2.0.2 (see [datum-cloud/infra#3333](https://github.com/datum-cloud/infra/issues/3333)).*

### Changed
- Rebase the Datum value-add (per-host config overrides, WAF instance cache, CEL metadata extraction, OpenTelemetry tracing/metrics, and the multi-arch payload image) onto upstream **v2.0.2** (Coraza `v3.7.0`, CRS 4.25), replacing the stale `v1.3.0-alpha` lineage.
- Keep the downstream config contract: `directives` and `host_directive_map` remain embedded JSON strings (upstream v2.0.0 switched to native YAML maps). The network-services-operator extension server emits JSON strings, so the parser retains the pre-v2.0 behaviour.
- Add back-compat CRS include aliases `@recommended-conf` and `@crs-setup-conf` (mapped to the renamed `coraza.conf` / `crs-setup.conf`) so directives emitted downstream keep resolving against the upstream `coreruleset/` layout.
- Pin Envoy to `v1.37.1` to match the edge proxy ABI (upstream moved to v1.38.1).

### Security
- Bump Go toolchain to 1.25.12 and upgrade OpenTelemetry (v1.43.0), gRPC (v1.80.0), `golang.org/x/net`, and `golang.org/x/sys` to clear the govulncheck-reported CVEs (GO-2026-*) in called code, so the `Vulnerability Scan` gate runs green. ([datum-cloud/infra#3336](https://github.com/datum-cloud/infra/issues/3336))

### Fixed
- Deliver response-body-phase WAF blocks: hold the upstream response headers (`StopAndBufferWatermark`, not `Continue`, on non-final `EncodeData` chunks) until the response-body verdict, so an Enforce block emits its branded local reply instead of committing the origin `200` (silent bypass) or resetting mid-stream. Drop the zero-fill `buffer.Set` on the local-reply path (empty body on Envoy 1.37.x). Requires `SecResponseBodyLimit <= per_connection_buffer_limit_bytes`. ([datum-cloud/infra#3324](https://github.com/datum-cloud/infra/issues/3324), [#3329](https://github.com/datum-cloud/infra/issues/3329))

## [v2.0.2] - 2026-06-09

### Changed
- Publish the Envoy Coraza image for both amd64 and arm64 platforms. ([#109](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/109)) ([aslafy-z](https://github.com/aslafy-z))

## [v2.0.1] - 2026-06-05

*Security release mitigating [CVE-2026-47774](https://github.com/envoyproxy/envoy/security/advisories/GHSA-22m2-hvr2-xqc8)*

### Changed

- Update envoy to version 1.38.1 ([#112](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/112))([#113](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/113))
- Update go to version 1.26.4 ([kabbohus](https://github.com/kabbohus))

## [v2.0.0] - 2026-05-19

*The included configuration files have changed. Please consult the [updated README section](./README.md#using-crs) for details.*

### Added
- Add support for per route and per virtual host level configuration ([98](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/98))([daum3ns](https://github.com/daum3ns))
- Add support to load rules from filesystem ([#97](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/97))([daum3ns](https://github.com/daum3ns))
- Build and publish docker image. Describe usage in EnvoyGateway ([#91](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/91))([daum3ns](https://github.com/daum3ns))

### Changed
- **Breaking:** `directives` and `host_directive_map` are now native YAML maps instead of embedded JSON strings. Old configs using `|` block scalars with JSON must be converted to plain YAML. See [README](./README.md#configuration) for examples. ([#106](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/106))([daum3ns](https://github.com/daum3ns))
- **Breaking:** Update CRS to version 4.25 ([#81](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/80))([daum3ns](https://github.com/daum3ns))
- Update envoy to version 1.38.0 ([#101](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/101))([daum3ns](https://github.com/daum3ns)) ([#79](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/79))([daum3ns](https://github.com/daum3ns))
- Update go to version 1.25.9 ([#77](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/77))([daum3ns](https://github.com/daum3ns))
- Update coraza to version 3.7.0 ([#71](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/71))([kabbohus](https://github.com/kabbohus)) ([#74](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/74))([kabbohus](https://github.com/kabbohus)) ([#75](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/75))([kabbohus](https://github.com/kabbohus))
- The Coraza filter now automatically appends the appropriate port (HTTP or HTTPS) to the Host header when no direct match is found in the host directive map. If a match is still not found, it gracefully falls back to the default directive. ([#73](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/73))([kabbohus](https://github.com/kabbohus))
- `host_directive_map` lookup order has changed to: (1) exact match on the Host header as received (e.g. `myhost:8080`), (2) if the Host header contains a port, strip it and retry (e.g. `myhost`), (3) fall back to the default directive. To match traffic on a specific port only, include the port in the key (e.g. `myhost:80`, `myhost:443`). A bare hostname key (e.g. `myhost`) matches any port not covered by a more specific entry. ([#103](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/103))([kabbohus](https://github.com/kabbohus))
- Switch to using slog for logging ([#67](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/67))([kabbohus](https://github.com/kabbohus)) ([#70](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/70))([kabbohus](https://github.com/kabbohus))

## [v1.3.0] - 2026-03-12

### Changed
- Update coraza to version 3.4.0 ([#69](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/69))([kabbohus](https://github.com/kabbohus))
- Update envoy to version 1.37.1 ([#69](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/69))([kabbohus](https://github.com/kabbohus))

### Fixed
- A bug in Coraza results in a wrong HTTP status code returned, if `SecResponseBodyLimit` is reached and `SecResponseBodyLimitAction` is set to `Reject`. Coraza incorrectly returns HTTP 413 instead of HTTP 500 ([#69](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/69))([kabbohus](https://github.com/kabbohus))

## [v1.2.3] - 2026-03-06

### Fixed
- Add support for HTTP tunnels using CONNECT method ([#66](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/66))([kabbohus](https://github.com/kabbohus))
- Fix HTTP request arrive at backend despite request being blocked after body was validated. ([#66](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/66))([kabbohus](https://github.com/kabbohus))

### Changed
- Deprecate the "plain" log format in favor of "text" ([#65](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/65))([kabbohus](https://github.com/kabbohus))

### Known Issues
- A bug in Coraza results in a wrong HTTP status code returned, if `SecResponseBodyLimit` is reached and `SecResponseBodyLimitAction` is set to `Reject`. Coraza incorrectly returns HTTP 413 instead of HTTP 500. ([corazawaf/coraza#1377](https://github.com/corazawaf/coraza/issues/1377))

## [v1.2.2] - 2026-02-27

### Fixed
- Fix HTTP headers arrive at backend despite the request being blocked in the later phase for header only requests ([#61](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/64))([kabbohus](https://github.com/kabbohus))

### Known Issues
- A bug in Coraza results in a wrong HTTP status code returned, if `SecResponseBodyLimit` is reached and `SecResponseBodyLimitAction` is set to `Reject`. Coraza incorrectly returns HTTP 413 instead of HTTP 500. ([corazawaf/coraza#1377](https://github.com/corazawaf/coraza/issues/1377))

## [v1.2.1] - 2026-02-16

### Changed
- Update go to version 1.25.7 ([kabbohus](https://github.com/kabbohus))

### Known Issues
- A bug in Coraza results in a wrong HTTP status code returned, if `SecResponseBodyLimit` is reached and `SecResponseBodyLimitAction` is set to `Reject`. Coraza incorrectly returns HTTP 413 instead of HTTP 500. ([corazawaf/coraza#1377](https://github.com/corazawaf/coraza/issues/1377))

## [v1.2.0] - 2026-02-13

### Added
- Set the memoize_builders flag to reduce memory consumption in deployments that launch several coraza instances. ([#42](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/42)) ([daum3ns](https://github.com/daum3ns))
- Add a new build target for improved performance on larger payloads. ([#45](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/45)) ([kabbohus](https://github.com/HusseinKabbout))

### Changed
- Update go to version 1.24.11 ([#40](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/40)) ([daum3ns](https://github.com/daum3ns)) ([48](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/48))
- Update envoy to 1.37.0 ([#37](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/37)) ([#49](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/49)) ([56](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/56))
- Update protobuf to 1.36.11 ([#37](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/37)) ([54](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/54))
- Migrate form `mage` to `make` ([#62](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/62)) ([kabbohus](https://github.com/HusseinKabbout))

### Fixed
- Fix HTTP headers arrive at backend despite the request being blocked in the later phase ([#61](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/61))([daum3ns](https://github.com/daum3ns))

### Known Issues
- A bug in Coraza results in a wrong HTTP status code returned, if `SecResponseBodyLimit` is reached and `SecResponseBodyLimitAction` is set to `Reject`. Coraza incorrectly returns HTTP 413 instead of HTTP 500. ([corazawaf/coraza#1377](https://github.com/corazawaf/coraza/issues/1377))

## [v1.1.1] - 2025-09-18

### Changed
- Update go to version 1.24.6 ([#32](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/32)) ([daum3ns](https://github.com/daum3ns))

## [v1.1.0] - 2025-09-18

### Changed
- Improved log messages ([#31](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/31)) ([daum3ns](https://github.com/daum3ns))
- Update envoy to 1.35.3 ([#27](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/27)) ([daum3ns](https://github.com/daum3ns))
- Update CRS to version 4.18.0 ([#23](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/23)) ([#26](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/26)) ([daum3ns](https://github.com/daum3ns)) ([kabbohus](https://github.com/HusseinKabbout))

### Known Issues
- A bug in Coraza results in a wrong HTTP status code returned, if `SecResponseBodyLimit` is reached and `SecResponseBodyLimitAction` is set to `Reject`. Coraza incorrectly returns HTTP 413 instead of HTTP 500. ([corazawaf/coraza#1377](https://github.com/corazawaf/coraza/issues/1377))

## [v1.0.0] - 2025-07-15

_First release._

### Changed
- Update CRS to version 4.16.0 ([#20](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/20)) ([daum3ns](https://github.com/daum3ns))
- Make log format configurable ([#9](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/9)) ([daum3ns](https://github.com/daum3ns))
- Update go to version 1.24.4 ([#14](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/14)) ([daum3ns](https://github.com/daum3ns))
- Return status code from coraza interruption ([#11](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/11)) ([daum3ns](https://github.com/daum3ns))
- Update envoy to v1.34 (#X) ([daum3ns](https://github.com/daum3ns))
- Update dependencies: coraza v3.3.3 and protobuf v1.36.6 (#X) ([daum3ns](https://github.com/daum3ns))


### Added
- Add changelog ([#8](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/8)) ([daum3ns](https://github.com/daum3ns))

### Fixed
- Fix filter disrupts websocket connections ([#18](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/18)) ([daum3ns](https://github.com/daum3ns))
- Fix wrong status code returned when reaching body limits ([#6](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/6)) ([daum3ns](https://github.com/daum3ns))
- Fix wrong status code returned ([#5](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/5)) ([daum3ns](https://github.com/daum3ns))
- Fix avoid response inspection if SecResponseBodyAccess is off ([#4](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/4/)) ([Armin Abfalterer](https://github.com/arminabf))
- Fix go-ftw testbench (#X) ([daum3ns](https://github.com/daum3ns))
- Fix rule exclusion via SecAction to not working (#X) ([daum3ns](https://github.com/daum3ns))

### Known Issues
- A bug in Coraza results in a wrong HTTP status code returned, if `SecResponseBodyLimit` is reached and `SecResponseBodyLimitAction` is set to `Reject`. Coraza incorrectly returns HTTP 413 instead of HTTP 500. ([corazawaf/coraza#1377](https://github.com/corazawaf/coraza/issues/1377))

[v2.0.2-datum.1]: https://github.com/datum-labs/coraza-envoy-go-filter/releases/tag/v2.0.2-datum.1
[v2.0.2]: https://github.com/united-security-providers/coraza-envoy-go-filter/releases/tag/v2.0.2
[v2.0.1]: https://github.com/united-security-providers/coraza-envoy-go-filter/releases/tag/v2.0.1
[v2.0.0]: https://github.com/united-security-providers/coraza-envoy-go-filter/releases/tag/v2.0.0
[v1.3.0]: https://github.com/united-security-providers/coraza-envoy-go-filter/releases/tag/v1.3.0
[v1.2.3]: https://github.com/united-security-providers/coraza-envoy-go-filter/releases/tag/v1.2.3
[v1.2.2]: https://github.com/united-security-providers/coraza-envoy-go-filter/releases/tag/v1.2.2
[v1.2.1]: https://github.com/united-security-providers/coraza-envoy-go-filter/releases/tag/v1.2.1
[v1.2.0]: https://github.com/united-security-providers/coraza-envoy-go-filter/releases/tag/v1.2.0
[v1.1.1]: https://github.com/united-security-providers/coraza-envoy-go-filter/releases/tag/v1.1.1
[v1.1.0]: https://github.com/united-security-providers/coraza-envoy-go-filter/releases/tag/v1.1.0
[v1.0.0]: https://github.com/united-security-providers/coraza-envoy-go-filter/releases/tag/v1.0.0
