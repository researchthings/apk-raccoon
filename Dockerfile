# =============================================================================
# APK Raccoon - Hardened Dockerfile
# =============================================================================
# Security features:
# - All downloaded binaries verified with SHA256 checksums
# - All tool versions explicitly pinned for reproducible builds
# - Multi-stage build to minimize final image size
# - Build-time verification of installed tools
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder - Download and verify all external tools
# -----------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# =============================================================================
# Tool versions and checksums - UPDATE THESE WHEN UPGRADING
# =============================================================================
# jadx 1.5.0
ENV JADX_VERSION=1.5.0
ENV JADX_SHA256=c5a713fa4800cbb9e6df85ced1bef95ba329040c95cb87d54465f108483e4ef9

# apktool 2.9.3
ENV APKTOOL_VERSION=2.9.3
ENV APKTOOL_SHA256=7956eb04194300ce0d0a84ad18771eebc94b89fb8d1ddcce8ea4c056818646f4

# Android command-line tools (11076708 = latest as of 2024)
ENV CMDLINE_TOOLS_VERSION=11076708
ENV CMDLINE_TOOLS_SHA256=2d2d50857e4eb553af5a6dc3ad507a17adf43d115264b1afc116f95c92e5e258

# syft - pinned version
ENV SYFT_VERSION=1.18.1
ENV SYFT_SHA256=066c251652221e4d44fcc4d115ce3df33a91769da38c830a8533199db2f65aab

# grype - pinned version
ENV GRYPE_VERSION=0.86.1
ENV GRYPE_SHA256=2d1533dae213a27b741e0cb31b2cd354159a283325475512ae90c1c2412f4098

# =============================================================================
# Download and verify jadx
# =============================================================================
RUN echo "Downloading jadx ${JADX_VERSION}..." && \
    wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -O jadx.zip && \
    echo "${JADX_SHA256}  jadx.zip" | sha256sum -c - && \
    unzip -q jadx.zip -d /build/jadx && \
    rm jadx.zip

# =============================================================================
# Download and verify apktool
# =============================================================================
RUN echo "Downloading apktool ${APKTOOL_VERSION}..." && \
    wget -q "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar" -O /build/apktool.jar && \
    echo "${APKTOOL_SHA256}  /build/apktool.jar" | sha256sum -c -

# =============================================================================
# Download and verify Android command-line tools
# =============================================================================
RUN echo "Downloading Android cmdline-tools..." && \
    wget -q "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip" -O cmdline-tools.zip && \
    echo "${CMDLINE_TOOLS_SHA256}  cmdline-tools.zip" | sha256sum -c - && \
    unzip -q cmdline-tools.zip -d /build/cmdline-tools && \
    rm cmdline-tools.zip

# =============================================================================
# Download and verify syft (direct binary instead of install script)
# =============================================================================
RUN echo "Downloading syft ${SYFT_VERSION}..." && \
    wget -q "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" -O syft.tar.gz && \
    echo "${SYFT_SHA256}  syft.tar.gz" | sha256sum -c - && \
    tar -xzf syft.tar.gz syft && \
    chmod +x syft && \
    rm syft.tar.gz

# =============================================================================
# Download and verify grype (direct binary instead of install script)
# =============================================================================
RUN echo "Downloading grype ${GRYPE_VERSION}..." && \
    wget -q "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" -O grype.tar.gz && \
    echo "${GRYPE_SHA256}  grype.tar.gz" | sha256sum -c - && \
    tar -xzf grype.tar.gz grype && \
    chmod +x grype && \
    rm grype.tar.gz

# -----------------------------------------------------------------------------
# Stage 2: Runtime - Build the final minimal image
# -----------------------------------------------------------------------------
FROM python:3.11-slim-bookworm

# Labels for image metadata
LABEL maintainer="Randy Grant <rgrant.research@gmail.com>"
LABEL description="APK Raccoon - Android APK Security Scanner with OWASP MASVS/MSTG coverage"
LABEL version="2.0"

# Install only runtime dependencies (no wget/curl needed in final image)
RUN apt-get update && apt-get install -y --no-install-recommends \
    unzip zip openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set up Android SDK paths
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV PATH=${PATH}:${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/platform-tools:${ANDROID_SDK_ROOT}/build-tools/34.0.0

# Create SDK directories
RUN mkdir -p ${ANDROID_SDK_ROOT}/cmdline-tools /root/.android && \
    touch /root/.android/repositories.cfg

# Copy verified tools from builder stage
COPY --from=builder /build/jadx /opt/jadx
COPY --from=builder /build/apktool.jar /opt/apktool.jar
COPY --from=builder /build/cmdline-tools/cmdline-tools ${ANDROID_SDK_ROOT}/cmdline-tools/latest
COPY --from=builder /build/syft /usr/local/bin/syft
COPY --from=builder /build/grype /usr/local/bin/grype

# Create tool symlinks and wrappers
RUN ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    echo '#!/bin/bash\njava -jar /opt/apktool.jar "$@"' > /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool

# Accept Android SDK licenses and install SDK components
RUN yes | sdkmanager --licenses > /dev/null 2>&1 && \
    sdkmanager --sdk_root=${ANDROID_SDK_ROOT} \
        "platform-tools" \
        "platforms;android-34" \
        "build-tools;34.0.0" \
    && rm -rf /root/.android/cache

# Install UV (pinned version via specific tag)
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /usr/local/bin/uv

# Set workdir and copy project
WORKDIR /app
COPY requirements.txt /app/
COPY pyproject.toml /app/

# Install Python dependencies
RUN uv pip install --system --no-cache -r requirements.txt

# Copy application code (after deps for better layer caching)
COPY bin/ /app/bin/
COPY data/ /app/data/
COPY raccoon.sh /app/

# =============================================================================
# Build-time verification - Ensure all tools work
# =============================================================================
RUN echo "=== Build Verification ===" && \
    echo "Verifying jadx..." && jadx --version && \
    echo "Verifying apktool..." && apktool --version && \
    echo "Verifying syft..." && syft version && \
    echo "Verifying grype..." && grype version && \
    echo "Verifying sdkmanager..." && sdkmanager --version && \
    echo "Verifying Python deps..." && python3 -c "import androguard; import pandas; import yaml; import lxml; print('Python deps OK')" && \
    echo "Verifying scanner scripts..." && \
    for script in bin/*.py; do python3 -m py_compile "$script" && echo "  $script OK"; done && \
    echo "=== All verifications passed ==="

# Security: Run as non-root user (optional, uncomment if needed)
# RUN useradd -m -s /bin/bash scanner
# USER scanner

# Set default entrypoint
ENTRYPOINT ["bash", "raccoon.sh", "--no-setup"]
CMD ["--help"]

# =============================================================================
# Build instructions:
#   docker build -t apk-raccoon .
#
# Run instructions:
#   docker run --rm -v /path/to/apks:/input -v /path/to/output:/output \
#     -e AUDIT_DIR=/output apk-raccoon /input/app.apk
#
# To update tool versions:
#   1. Update ENV *_VERSION variables above
#   2. Download new releases and compute SHA256:
#      sha256sum jadx-X.Y.Z.zip
#   3. Update ENV *_SHA256 variables
#   4. Rebuild image
# =============================================================================
