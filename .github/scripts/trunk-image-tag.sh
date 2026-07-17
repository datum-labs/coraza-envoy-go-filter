#!/usr/bin/env bash
set -euo pipefail

sha="${GITHUB_SHA:?}"
short_sha="${sha:0:7}"
timestamp="$(date -u +%Y%m%d-%H%M%S)"
image_tag="v0.0.0-main-${timestamp}-${short_sha}"

echo "image_tag=${image_tag}" >> "${GITHUB_OUTPUT:?}"
