#!/usr/bin/env bash
set -euo pipefail

tag="${GITHUB_REF_NAME:?}"
image_tag="${tag%%+*}"
base=""
case "$tag" in
  *+upstream.*) base="${tag##*+upstream.}" ;;
esac

{
  echo "image_tag=${image_tag}"
  echo "upstream_base=${base}"
} >> "${GITHUB_OUTPUT:?}"
