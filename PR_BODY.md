# feat: multi-arch (linux/amd64 + linux/arm64) container image

## Summary

- **Problem:** `ghcr.io/datum-labs/coraza-envoy-go-filter/coraza-waf` was published as an
  amd64-only image. On Apple Silicon (arm64) the `coraza-waf.so` inside the image cannot
  be loaded by Envoy at runtime (`dlopen` fails — native code, no in-process emulation).
  This blocked WAF e2e testing on any arm64 workstation or runner.

- **Fix:** Restructured the Dockerfile to include a self-contained multi-stage build
  (no pre-built `.so` required in the build context) and added a new GitHub Actions
  workflow (`publish-image.yml`) that builds and pushes a multi-arch manifest list
  covering `linux/amd64` and `linux/arm64` to ghcr.io on every tag push.

## What changed

### `Dockerfile` — multi-stage build with cross-compilation

**Before:** A two-line image that just `COPY coraza-waf.so /coraza-waf.so` into scratch.
The `.so` had to be pre-built outside Docker and injected via the build context; no CI
pipeline was wiring this into ghcr.io.

**After:** Two-stage build:

1. **`builder` stage** (`FROM --platform=$BUILDPLATFORM golang:1.24-bookworm`)  
   Always runs on the builder's native architecture (amd64 on `ubuntu-latest` CI).
   Installs the appropriate GNU cross-toolchain when `BUILDPLATFORM ≠ TARGETPLATFORM`:
   - `amd64 → arm64`: `gcc-aarch64-linux-gnu` / `aarch64-linux-gnu-gcc`
   - `arm64 → amd64`: `gcc-x86-64-linux-gnu` / `x86_64-linux-gnu-gcc`
   - `native → native`: stock `gcc`, no extra packages
   
   Key fix: **`ARG TARGETARCH` is declared without a default value.** An explicit default
   (e.g. `=amd64`) silently prevents BuildKit from injecting the real platform value —
   this was the root cause of silent wrong-arch builds.

2. **Final stage** (`FROM ${BASE_IMAGE:-scratch}`)  
   Copies only `/coraza-waf.so` from the builder. Unchanged semantics from the original.

### `.github/workflows/publish-image.yml` — new workflow

Triggers on `v*.*.*` tag pushes (covers both pre-releases like `v1.3.0-alpha4` and final
releases) plus `workflow_dispatch` for manual builds.

Pattern used (same as upstream `united-security-providers` PR #109):

1. **Matrix build** — two `ubuntu-latest` (amd64) jobs, one per platform
   (`linux/amd64`, `linux/arm64`), using the cross-compilation Dockerfile.
   Each job pushes by digest (no tag yet).
2. **Merge job** — downloads both digests, runs `docker buildx imagetools create`
   to publish a single manifest list with the standard semver tags
   (`{{version}}`, `{{major}}.{{minor}}`, `{{major}}`, plus the raw git tag).

QEMU is installed in each build job (`docker/setup-qemu-action@v3`) as a
belt-and-suspenders measure; the build stage itself does not execute under
QEMU because `FROM --platform=$BUILDPLATFORM` keeps compilation on the host arch.

## Validation

Built and verified locally using Colima (linux/arm64 native) + `multiarch-test` buildx builder:

```
# arm64 build
$ docker buildx build --platform linux/arm64 --output type=local,dest=/tmp/arm64 .
$ file /tmp/arm64/coraza-waf.so
coraza-waf.so: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV),
               dynamically linked, BuildID[sha1]=f13b3314d521..., with debug_info

# amd64 build (cross-compiled arm64→amd64 from Colima)
$ docker buildx build --platform linux/amd64 --output type=local,dest=/tmp/amd64 .
$ file /tmp/amd64/coraza-waf.so
coraza-waf.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
               dynamically linked, BuildID[sha1]=ba0fc72b9049..., with debug_info
```

Both platform builds succeed and produce correctly typed ELF shared objects.

Full Envoy load-testing (dlopen at runtime) is out of scope for this PR; that
requires a live Envoy binary in the target environment.

## Blockers / decisions for human review

1. **`workflow_dispatch` triggers an image push with no semver tag** — for branch-based
   manual runs the image is tagged with the branch/SHA ref only.  If datum-labs needs
   consistent tagging for manual pre-release builds, a separate tagging strategy or
   input parameter can be added.

2. **Native ARM runners as an alternative** — GitHub now offers `ubuntu-24.04-arm`
   hosted runners.  Using them eliminates the need for any cross-toolchain and is the
   approach used by the upstream repo (PR #109).  If datum-labs has access to those
   runners, swap `runs-on: ubuntu-latest` → `runs-on: ${{ matrix.runner }}` with a
   `runner` matrix that maps `linux/amd64 → ubuntu-latest` and
   `linux/arm64 → ubuntu-24.04-arm`.  This is purely an optimization — the
   cross-compilation approach produces identical binaries.

3. **Release workflow (`release.yml`) unchanged** — it still builds the `.so` natively
   on the CI runner (amd64 only) for GitHub Release assets.  The new workflow covers
   the OCI image path.  If per-arch `.so` release assets are also wanted, that's a
   separate change.

4. **No signing/attestation** — the image is not signed with Cosign or attested.
   Add `docker/attest-build-provenance-action` if SLSA provenance is required.
