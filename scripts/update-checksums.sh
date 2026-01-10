#!/usr/bin/env bash
# =============================================================================
# Helper script to compute SHA256 checksums for Dockerfile dependencies
# Run this when updating tool versions to get correct checksums
# =============================================================================

set -euo pipefail

# Tool versions - update these to match Dockerfile
JADX_VERSION="1.5.0"
APKTOOL_VERSION="2.9.3"
CMDLINE_TOOLS_VERSION="11076708"
SYFT_VERSION="1.18.1"
GRYPE_VERSION="0.86.1"

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "=== Computing SHA256 checksums for Docker dependencies ==="
echo "Temp directory: $TMPDIR"
echo ""

# jadx
echo "Downloading jadx ${JADX_VERSION}..."
wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -O "$TMPDIR/jadx.zip"
JADX_SHA=$(sha256sum "$TMPDIR/jadx.zip" | cut -d' ' -f1)
echo "JADX_SHA256=${JADX_SHA}"
echo ""

# apktool
echo "Downloading apktool ${APKTOOL_VERSION}..."
wget -q "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar" -O "$TMPDIR/apktool.jar"
APKTOOL_SHA=$(sha256sum "$TMPDIR/apktool.jar" | cut -d' ' -f1)
echo "APKTOOL_SHA256=${APKTOOL_SHA}"
echo ""

# Android command-line tools
echo "Downloading Android cmdline-tools ${CMDLINE_TOOLS_VERSION}..."
wget -q "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip" -O "$TMPDIR/cmdline-tools.zip"
CMDLINE_SHA=$(sha256sum "$TMPDIR/cmdline-tools.zip" | cut -d' ' -f1)
echo "CMDLINE_TOOLS_SHA256=${CMDLINE_SHA}"
echo ""

# syft
echo "Downloading syft ${SYFT_VERSION}..."
wget -q "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" -O "$TMPDIR/syft.tar.gz"
SYFT_SHA=$(sha256sum "$TMPDIR/syft.tar.gz" | cut -d' ' -f1)
echo "SYFT_SHA256=${SYFT_SHA}"
echo ""

# grype
echo "Downloading grype ${GRYPE_VERSION}..."
wget -q "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" -O "$TMPDIR/grype.tar.gz"
GRYPE_SHA=$(sha256sum "$TMPDIR/grype.tar.gz" | cut -d' ' -f1)
echo "GRYPE_SHA256=${GRYPE_SHA}"
echo ""

echo "=== Summary - Copy these to Dockerfile ==="
cat <<EOF

# jadx ${JADX_VERSION}
ENV JADX_VERSION=${JADX_VERSION}
ENV JADX_SHA256=${JADX_SHA}

# apktool ${APKTOOL_VERSION}
ENV APKTOOL_VERSION=${APKTOOL_VERSION}
ENV APKTOOL_SHA256=${APKTOOL_SHA}

# Android command-line tools
ENV CMDLINE_TOOLS_VERSION=${CMDLINE_TOOLS_VERSION}
ENV CMDLINE_TOOLS_SHA256=${CMDLINE_SHA}

# syft ${SYFT_VERSION}
ENV SYFT_VERSION=${SYFT_VERSION}
ENV SYFT_SHA256=${SYFT_SHA}

# grype ${GRYPE_VERSION}
ENV GRYPE_VERSION=${GRYPE_VERSION}
ENV GRYPE_SHA256=${GRYPE_SHA}

EOF

echo "=== Done ==="
