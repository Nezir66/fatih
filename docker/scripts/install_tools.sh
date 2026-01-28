#!/bin/bash
set -e

echo "=== Installing ProjectDiscovery and Security Tools ==="

# Tool versions (pinned for reproducibility)
SUBFINDER_VERSION="2.6.3"
NAABU_VERSION="2.3.0"
HTTPX_VERSION="1.3.7"
NUCLEI_VERSION="3.1.10"
KATANA_VERSION="1.0.5"
FFUF_VERSION="2.1.0"
NIKTO_VERSION="2.5.0"
WHATWEB_VERSION="0.6.3"

# Create temporary directory
TEMP_DIR="/tmp/tools_install"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

# Install Subfinder
echo "Installing Subfinder v${SUBFINDER_VERSION}..."
wget -q "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip"
unzip -o -q "subfinder_${SUBFINDER_VERSION}_linux_amd64.zip"
mv subfinder /usr/local/bin/
chmod +x /usr/local/bin/subfinder

# Install Naabu
echo "Installing Naabu v${NAABU_VERSION}..."
wget -q "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_amd64.zip"
unzip -o -q "naabu_${NAABU_VERSION}_linux_amd64.zip"
mv naabu /usr/local/bin/
chmod +x /usr/local/bin/naabu

# Install Httpx
echo "Installing Httpx v${HTTPX_VERSION}..."
wget -q "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip"
unzip -o -q "httpx_${HTTPX_VERSION}_linux_amd64.zip"
mv httpx /usr/local/bin/
chmod +x /usr/local/bin/httpx

# Install Nuclei
echo "Installing Nuclei v${NUCLEI_VERSION}..."
wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
unzip -o -q "nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
mv nuclei /usr/local/bin/
chmod +x /usr/local/bin/nuclei

# Install Katana
echo "Installing Katana v${KATANA_VERSION}..."
wget -q "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip"
unzip -o -q "katana_${KATANA_VERSION}_linux_amd64.zip"
mv katana /usr/local/bin/
chmod +x /usr/local/bin/katana

# Install ffuf
echo "Installing ffuf v${FFUF_VERSION}..."
wget -q "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz"
tar -xzf "ffuf_${FFUF_VERSION}_linux_amd64.tar.gz"
mv ffuf /usr/local/bin/
chmod +x /usr/local/bin/ffuf

# Install Nikto (manually from GitHub for latest version)
echo "Installing Nikto v${NIKTO_VERSION} from source..."
git clone --depth 1 --branch ${NIKTO_VERSION} https://github.com/sullo/nikto.git /opt/nikto
ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto
chmod +x /opt/nikto/program/nikto.pl

# Install WhatWeb (manually from GitHub for latest version)
echo "Installing WhatWeb v${WHATWEB_VERSION} from source..."
git clone --depth 1 --branch v${WHATWEB_VERSION} https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb
cd /opt/whatweb
# Install Ruby dependencies
bundle install --system
cd "$TEMP_DIR"
ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb
chmod +x /opt/whatweb/whatweb

# Update Nuclei templates
echo "Updating Nuclei templates..."
nuclei -update-templates -silent || true

# Cleanup
echo "Cleaning up temporary files..."
cd /
rm -rf "$TEMP_DIR"

# Verify installations
echo ""
echo "=== Verification ==="
echo "Subfinder: $(subfinder -version 2>&1 | head -n1 || echo 'FAILED')"
echo "Naabu: $(naabu -version 2>&1 | head -n1 || echo 'FAILED')"
echo "Httpx: $(httpx -version 2>&1 | head -n1 || echo 'FAILED')"
echo "Nuclei: $(nuclei -version 2>&1 | head -n1 || echo 'FAILED')"
echo "Katana: $(katana -version 2>&1 | head -n1 || echo 'FAILED')"
echo "ffuf: $(ffuf -V 2>&1 | head -n1 || echo 'FAILED')"
echo "Nikto: $(nikto -Version 2>&1 | grep 'Nikto v' || echo 'FAILED')"
echo "WhatWeb: $(whatweb --version 2>&1 | head -n1 || echo 'FAILED')"
echo "Nmap (from apt): $(nmap --version 2>&1 | head -n1 || echo 'FAILED')"
echo ""
echo "=== All tools installed successfully! ==="
