#!/bin/bash
# Verification script for Debian Bookworm migration
# Run this inside the Docker container: docker-compose exec fatih /app/verify_migration.sh

set -e

echo "========================================="
echo "Fatih Docker Migration Verification"
echo "========================================="
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0

# Test function
test_tool() {
    local tool_name=$1
    local test_command=$2
    local expected_pattern=$3

    echo -n "Testing ${tool_name}... "

    if output=$(eval "$test_command" 2>&1); then
        if echo "$output" | grep -q "$expected_pattern"; then
            echo -e "${GREEN}✓ PASS${NC}"
            ((PASSED++))
            return 0
        else
            echo -e "${YELLOW}⚠ WARN${NC} (unexpected output)"
            echo "  Output: $output"
            ((FAILED++))
            return 1
        fi
    else
        echo -e "${RED}✗ FAIL${NC}"
        echo "  Error: $output"
        ((FAILED++))
        return 1
    fi
}

echo "=== System Information ==="
echo -n "OS: "
cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2
echo -n "Python: "
python3 --version
echo ""

echo "=== Security Tools ==="
test_tool "Nmap" "nmap --version" "Nmap version 7.9"
test_tool "Nikto" "nikto -Version" "Nikto v2.5"
test_tool "WhatWeb" "whatweb --version" "WhatWeb version 0.6"
test_tool "Subfinder" "subfinder -version" "v2.6.3"
test_tool "Naabu" "naabu -version" "v2.3.0"
test_tool "Httpx" "httpx -version" "v1.3.7"
test_tool "Nuclei" "nuclei -version" "v3.1.10"
test_tool "Katana" "katana -version" "v1.0.5"
test_tool "ffuf" "ffuf -V" "v2.1.0"
echo ""

echo "=== Python Dependencies ==="
test_tool "Anthropic SDK" "python3 -c 'import anthropic; print(\"ok\")'" "ok"
test_tool "OpenAI SDK" "python3 -c 'import openai; print(\"ok\")'" "ok"
test_tool "PyYAML" "python3 -c 'import yaml; print(\"ok\")'" "ok"
test_tool "Docker SDK" "python3 -c 'import docker; print(\"ok\")'" "ok"
test_tool "Requests" "python3 -c 'import requests; print(\"ok\")'" "ok"
test_tool "Rich" "python3 -c 'import rich; print(\"ok\")'" "ok"
echo ""

echo "=== File Locations ==="
echo -n "Nikto source: "
if [ -d "/opt/nikto" ]; then
    echo -e "${GREEN}✓ /opt/nikto exists${NC}"
    ((PASSED++))
else
    echo -e "${RED}✗ /opt/nikto missing${NC}"
    ((FAILED++))
fi

echo -n "WhatWeb source: "
if [ -d "/opt/whatweb" ]; then
    echo -e "${GREEN}✓ /opt/whatweb exists${NC}"
    ((PASSED++))
else
    echo -e "${RED}✗ /opt/whatweb missing${NC}"
    ((FAILED++))
fi

echo -n "Nikto symlink: "
if [ -L "/usr/local/bin/nikto" ]; then
    echo -e "${GREEN}✓ /usr/local/bin/nikto linked${NC}"
    ((PASSED++))
else
    echo -e "${RED}✗ /usr/local/bin/nikto not linked${NC}"
    ((FAILED++))
fi

echo -n "WhatWeb symlink: "
if [ -L "/usr/local/bin/whatweb" ]; then
    echo -e "${GREEN}✓ /usr/local/bin/whatweb linked${NC}"
    ((PASSED++))
else
    echo -e "${RED}✗ /usr/local/bin/whatweb not linked${NC}"
    ((FAILED++))
fi
echo ""

echo "=== Smoke Tests ==="
echo -n "Nmap localhost scan: "
if nmap -sn 127.0.0.1 >/dev/null 2>&1; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAILED++))
fi

echo -n "Nuclei templates: "
if nuclei -templates-version >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Templates installed${NC}"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ WARN${NC} (templates may need update)"
    ((FAILED++))
fi
echo ""

echo "========================================="
echo "Results Summary"
echo "========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed! Migration successful.${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠ Some tests failed. Review output above.${NC}"
    exit 1
fi
