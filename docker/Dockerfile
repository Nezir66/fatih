# Fatih Autonomous Penetration Testing Agent - Docker Image
# Base: Debian Bookworm Slim (LTS, stable, production-ready)

FROM debian:bookworm-slim

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update system and install apt-available tools
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    # Core security tools (nmap 7.93 from Debian repos)
    nmap \
    # Utilities
    curl \
    wget \
    jq \
    git \
    unzip \
    tar \
    ca-certificates \
    # Python environment
    python3 \
    python3-pip \
    python3-venv \
    # Build tools (for some Python packages)
    build-essential \
    python3-dev \
    # Runtime dependencies for manually installed tools
    perl \
    ruby \
    ruby-bundler \
    ruby-dev \
    libyaml-dev \
    # Networking tools
    netcat-traditional \
    dnsutils \
    # Playwright/Chromium dependencies for headless browser
    chromium \
    chromium-driver \
    libnss3 \
    libatk-bridge2.0-0 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpangocairo-1.0-0 \
    libgtk-3-0 \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for running scans
RUN useradd -m -s /bin/bash -u 1000 scanner && \
    mkdir -p /app /workspace && \
    chown -R scanner:scanner /app /workspace

# Copy tool installation script
COPY docker/scripts/install_tools.sh /tmp/install_tools.sh
RUN chmod +x /tmp/install_tools.sh

# Install security tools (Katana, Nikto, WhatWeb)
RUN /tmp/install_tools.sh && rm /tmp/install_tools.sh

# Copy verification script for testing
COPY docker/scripts/verify_migration.sh /tmp/verify_migration.sh
RUN chmod +x /tmp/verify_migration.sh

# Set working directory
WORKDIR /app

# Copy Python requirements
COPY requirements.txt /app/requirements.txt

# Create Python virtual environment and install dependencies (PEP 668 compliant)
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt && \
    /opt/venv/bin/playwright install chromium

# Add venv to PATH so all Python commands use it
ENV PATH="/opt/venv/bin:${PATH}"

# Switch to non-root user
#USER scanner

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Default command (keeps container running for docker-compose exec)
CMD ["tail", "-f", "/dev/null"]
