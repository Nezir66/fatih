#!/bin/bash
set -e

echo "=== Installing ProjectDiscovery and Security Tools ==="
echo "Architecture: $(uname -m)"

# Tool versions
SUBFINDER_VERSION="v2.6.3"
NAABU_VERSION="v2.3.0"
HTTPX_VERSION="v1.3.7"
NUCLEI_VERSION="v3.1.10"
KATANA_VERSION="v1.0.5"
FFUF_VERSION="v2.1.0"
NIKTO_VERSION="2.5.0"
WHATWEB_VERSION="0.6.3"

# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
    GO_ARCH="arm64"
    echo "Detected ARM64 architecture"
else
    GO_ARCH="amd64"
    echo "Detected AMD64 architecture"
fi

# Install Go 1.21 for building Katana
echo "Installing Go 1.21..."
wget -q "https://go.dev/dl/go1.21.6.linux-${GO_ARCH}.tar.gz"
tar -C /usr/local -xzf "go1.21.6.linux-${GO_ARCH}.tar.gz"
rm "go1.21.6.linux-${GO_ARCH}.tar.gz"

export PATH="/usr/local/go/bin:$PATH"
export GOPATH=/opt/go
export GOBIN=/usr/local/bin
mkdir -p $GOPATH

# Function to download and install binary
download_and_install() {
    local tool_name=$1
    local version=$2
    local url=$3
    local filename=$4
    local extract_cmd=$5
    
    echo "Installing ${tool_name} ${version}..."
    
    if wget -q "$url" 2>/dev/null; then
        case "$extract_cmd" in
            "unzip")
                unzip -o -q "$filename"
                ;;
            "tar")
                tar -xzf "$filename"
                ;;
        esac
        
        mv "$tool_name" /usr/local/bin/ 2>/dev/null || true
        chmod +x /usr/local/bin/"$tool_name" 2>/dev/null || true
        rm -f "$filename"
        echo "  ✓ ${tool_name} installed"
    else
        echo "  ✗ Failed to download ${tool_name}"
        return 1
    fi
}

# Create temp directory
TEMP_DIR="/tmp/tools_install"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

# Install Katana from source (ARM64 compatible)
echo "Installing Katana ${KATANA_VERSION} from source..."
go install github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}

# Install other tools from AMD64 binaries (will use emulation on ARM64)
echo ""
echo "Installing other tools from AMD64 binaries..."
echo "Note: These will run through emulation on ARM64 (slower but functional)"

# Try to install AMD64 versions as fallback
download_and_install "subfinder" "$SUBFINDER_VERSION" \
    "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION#v}_linux_amd64.zip" \
    "subfinder_${SUBFINDER_VERSION#v}_linux_amd64.zip" \
    "unzip" || true

download_and_install "naabu" "$NAABU_VERSION" \
    "https://github.com/projectdiscovery/naabu/releases/download/${NAABU_VERSION}/naabu_${NAABU_VERSION#v}_linux_amd64.zip" \
    "naabu_${NAABU_VERSION#v}_linux_amd64.zip" \
    "unzip" || true

download_and_install "httpx" "$HTTPX_VERSION" \
    "https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_linux_amd64.zip" \
    "httpx_${HTTPX_VERSION#v}_linux_amd64.zip" \
    "unzip" || true

download_and_install "nuclei" "$NUCLEI_VERSION" \
    "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" \
    "nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" \
    "unzip" || true

download_and_install "ffuf" "$FFUF_VERSION" \
    "https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VERSION#v}_linux_amd64.tar.gz" \
    "ffuf_${FFUF_VERSION#v}_linux_amd64.tar.gz" \
    "tar" || true

# Install Nikto (manually from GitHub)
echo "Installing Nikto v${NIKTO_VERSION}..."
git clone --depth 1 --branch ${NIKTO_VERSION} https://github.com/sullo/nikto.git /opt/nikto
ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto
chmod +x /opt/nikto/program/nikto.pl

# Install WhatWeb (manually from GitHub)
echo "Installing WhatWeb v${WHATWEB_VERSION}..."
git clone --depth 1 --branch v${WHATWEB_VERSION} https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb
cd /opt/whatweb
bundle install --system
cd "$TEMP_DIR"
ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb
chmod +x /opt/whatweb/whatweb

# Cleanup Go build cache
go clean -cache
rm -rf $GOPATH/pkg

# Cleanup temp files
cd /
rm -rf "$TEMP_DIR"

# Install SecLists wordlists for fuzzing
echo ""
echo "Installing SecLists wordlists..."
git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
# Clean up unnecessary files to save space
rm -rf /usr/share/seclists/.git
rm -rf /usr/share/seclists/Passwords  # We don't need password lists for directory fuzzing
rm -rf /usr/share/seclists/Fuzzing    # Remove fuzzing payloads to save space
echo "  SecLists installed to /usr/share/seclists"

echo ""
echo "=== Verification ==="
echo "Katana: $(katana -version 2>&1 | head -n1 || echo 'NOT INSTALLED')"
echo "Subfinder: $(subfinder -version 2>&1 | head -n1 || echo 'NOT INSTALLED')"
echo "Naabu: $(naabu -version 2>&1 | head -n1 || echo 'NOT INSTALLED')"
echo "Httpx: $(httpx -version 2>&1 | head -n1 || echo 'NOT INSTALLED')"
echo "Nuclei: $(nuclei -version 2>&1 | head -n1 || echo 'NOT INSTALLED')"
echo "ffuf: $(ffuf -V 2>&1 | head -n1 || echo 'NOT INSTALLED')"
echo "Nikto: $(nikto -Version 2>&1 | grep 'Nikto v' || echo 'NOT INSTALLED')"
echo "WhatWeb: $(whatweb --version 2>&1 | head -n1 || echo 'NOT INSTALLED')"
echo "Nmap: $(nmap --version 2>&1 | head -n1 || echo 'NOT INSTALLED')"
echo ""
echo "=== Installation complete! ==="
echo "Note: Katana runs natively on ARM64."
echo "Other Go tools run through AMD64 emulation (may be slower)."
