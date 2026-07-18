# Releasing this fork

This is the Datum downstream fork of
[`united-security-providers/coraza-envoy-go-filter`](https://github.com/united-security-providers/coraza-envoy-go-filter).
It ships its **own** release line, independent of the upstream version. If the
release follows a rebase onto a newer upstream, read
[`MAINTAINING.md`](./MAINTAINING.md) first.

## Versioning

Releases use an own SemVer line, with the upstream base recorded as build
metadata:

```
git tag:    vMAJOR.MINOR.PATCH+upstream.<upstream-version>
image tag:  vMAJOR.MINOR.PATCH
```

- `MAJOR.MINOR.PATCH` is **ours**. It bumps on our changes and does not mirror
  the upstream version.
- `+upstream.<upstream-version>` is SemVer build metadata — e.g.
  `v2.0.3+upstream.2.0.2`. It records which upstream release we realigned onto
  and is **ignored for version precedence** (SemVer 2.0.0 §10), so it never
  affects ordering.
- The published container image is tagged with the bare `vMAJOR.MINOR.PATCH`
  because OCI tags cannot contain `+`. The upstream base is preserved on the
  image as the `org.opencontainers.image.base.version` label.

### Why not `-datum.N`

Earlier releases were tagged `vX.Y.Z-datum.N`, reusing the upstream version with
a `-datum.N` suffix. That suffix is a SemVer **pre-release** identifier
(SemVer 2.0.0 §9), so every release sorted *below* the plain upstream `vX.Y.Z`
of the same version, and default SemVer ranges (`>=x.y.z`) excluded it entirely.
Consumers had to add pre-release opt-ins and tag filters just to select our
builds. Owning the version line and moving provenance to build metadata removes
all of that: our releases are first-class releases that sort and match normally.

## Bump rules

- **Our change** (fix, feature, config-contract change): bump PATCH / MINOR /
  MAJOR by its impact on our consumers, per SemVer.
- **Realign onto a newer upstream** (see `MAINTAINING.md`): bump the version and
  update `+upstream.<version>` to the new base. The size of the bump follows the
  impact on our consumers — not the size of upstream's version jump.

## Cutting a release

A release is a **single tag push** — no pull request, no changelog edit.

1. Land all changes on `main` (protected — requires a green `Testbench` and one
   review).
2. Tag `main` with the full build-metadata tag and push it:
   ```
   git tag v2.0.3+upstream.2.0.2
   git push origin v2.0.3+upstream.2.0.2
   ```
3. `.github/workflows/release.yml` builds and pushes the image as
   `ghcr.io/datum-labs/coraza-envoy-go-filter/coraza-waf:v2.0.3`, stamps the
   `org.opencontainers.image.base.version` label with the upstream base, and
   publishes a GitHub Release. Release notes are **auto-generated** by GitHub
   from the merged PRs since the previous tag, grouped by label per
   `.github/release.yml`.

### Release notes

Notes come from GitHub's auto-generated release notes, not a committed file.
To shape them, label PRs (see `.github/release.yml` for the category mapping)
and write clear PR titles — the title is what appears in the notes.

`CHANGELOG.md` is retained as a **frozen** historical record up to `v2.0.3` but
is no longer hand-maintained per release; do not add new sections to it.

### Pre-releases

Release candidates and alphas keep the standard SemVer pre-release form —
`vX.Y.Z-rc.N`, `vX.Y.Z-alpha.N` — which `release.yml` publishes as GitHub
pre-releases. Do **not** use `-datum.N`: it is not a pre-release train, it was a
mislabel of full releases.

## Registry isolation (avoiding version collisions)

Only Datum builds are published to
`ghcr.io/datum-labs/coraza-envoy-go-filter`. Never republish an upstream plain
`vX.Y.Z` image into this registry — our own-line versions stay unambiguous only
while this registry holds our releases alone. Consumers pin this registry, so
the upstream version line never intersects ours.

## Consuming the images

Because releases are first-class SemVer, a Flux `ImagePolicy` selects them with
a plain range — no pre-release opt-in, no tag filter:

```yaml
  policy:
    semver:
      range: '>=2.0.0'
```
