# Copyright © 2025 United Security Providers AG, Switzerland
# Copyright © 2025 Datum Labs
# SPDX-License-Identifier: Apache-2.0

# BASE_IMAGE must be declared before the FROM that uses it.
ARG BASE_IMAGE=scratch

# ─── Build stage ────────────────────────────────────────────────────────────
# Pinned to the builder's native arch ($BUILDPLATFORM) so the Go toolchain
# runs at full native speed.  When TARGETPLATFORM ≠ BUILDPLATFORM we install
# the appropriate GNU cross-toolchain and let the Go cross-compiler do the
# rest — no QEMU emulation required during compilation.
FROM --platform=$BUILDPLATFORM golang:1.24-bookworm AS builder

# IMPORTANT: declare platform ARGs WITHOUT defaults inside the build stage.
# An explicit default (e.g. TARGETARCH=amd64) silently prevents BuildKit from
# injecting the real value from --platform and the build produces the wrong arch.
ARG BUILDPLATFORM
ARG TARGETPLATFORM
ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /build

# Install the correct GNU cross-toolchain when cross-compiling.
# native→native (BUILDPLATFORM == TARGETPLATFORM): no extra toolchain needed.
# amd64 → arm64: aarch64-linux-gnu-gcc
# arm64 → amd64: x86_64-linux-gnu-gcc   (for building amd64 images from Apple Silicon)
RUN if [ "${BUILDPLATFORM}" = "${TARGETPLATFORM}" ]; then \
      : ; \
    elif [ "${TARGETARCH}" = "arm64" ]; then \
      apt-get update && \
      apt-get install -y --no-install-recommends \
        gcc-aarch64-linux-gnu libc6-dev-arm64-cross && \
      rm -rf /var/lib/apt/lists/*; \
    elif [ "${TARGETARCH}" = "amd64" ]; then \
      apt-get update && \
      apt-get install -y --no-install-recommends \
        gcc-x86-64-linux-gnu libc6-dev-amd64-cross && \
      rm -rf /var/lib/apt/lists/*; \
    fi

# Cache module downloads as a separate layer.
COPY go.mod go.sum ./
RUN go mod download

# Copy only the plugin source; magefiles are not needed here.
COPY src/ ./src/

# Build the shared object.
# -buildmode=c-shared forces CGO_ENABLED=1.  The CC variable selects the
# correct cross-linker when the builder and target architectures differ.
RUN if [ "${BUILDPLATFORM}" = "${TARGETPLATFORM}" ]; then \
      CC_COMPILER="gcc"; \
    elif [ "${TARGETARCH}" = "arm64" ]; then \
      CC_COMPILER="aarch64-linux-gnu-gcc"; \
    elif [ "${TARGETARCH}" = "amd64" ]; then \
      CC_COMPILER="x86_64-linux-gnu-gcc"; \
    else \
      CC_COMPILER="gcc"; \
    fi && \
    CGO_ENABLED=1 \
    GOOS="${TARGETOS}" \
    GOARCH="${TARGETARCH}" \
    CC="${CC_COMPILER}" \
    go build \
      -o /coraza-waf.so \
      -buildmode=c-shared \
      -tags=coraza.rule.multiphase_evaluation \
      ./src

# ─── Final stage ────────────────────────────────────────────────────────────
# Minimal scratch image used purely as a transport vehicle: the operator mounts
# the .so into Envoy via a shared volume or init-container copy.
FROM ${BASE_IMAGE}
COPY --from=builder /coraza-waf.so /coraza-waf.so
