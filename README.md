<div align="center">

<img src="assets/images/logo.png" alt="Fatih Logo" width="200"/>

**The Autonomous AI Penetration Testing Agent**

[![Status](https://img.shields.io/badge/Status-Development-yellow)](https://github.com/Nezir66/fatih)
[![Docker](https://img.shields.io/badge/Docker-Debian_Bookworm-blue)](https://www.docker.com/)
[![AI](https://img.shields.io/badge/AI-LLM_Powered-purple)](https://openai.com/)

---

</div>

## 📖 Overview

**Fatih** is an LLM-driven security auditing tool designed for SaaS environments. Unlike static scanners, Fatih uses a **Reasoning Loop** (Observe → Orient → Decide → Act) to intelligently interact with web applications.

It runs in a secure, isolated **Docker** environment (The Body) controlled by a Cloud AI (The Brain).

## 🏗️ Architecture

| Component              | Tech Stack               | Description                                     |
| :--------------------- | :----------------------- | :---------------------------------------------- |
| **The Brain**          | OpenAI / Claude          | Decides strategy, analyzes code/responses.      |
| **The Body**           | Docker (Debian Bookworm) | Sandbox environment executing the tools.        |
| **The Nervous System** | Python 3.11+             | Orchestrates API calls and parses tool outputs. |
| **The Arsenal**        | Nmap, Nuclei, Subfinder  | Industry-standard CLI security tools.           |

## 🚀 Getting Started

### Prerequisites

- Docker & Docker Compose
- API Key (OpenAI or Anthropic)

### Installation

1.  **Clone the Repository**

    ```bash
    git clone https://github.com/Nezir66/fatih.git
    cd fatih
    ```

2.  **Configure Environment**
    Create a `.env` file in the root directory:

    ```ini
    OPENAI_API_KEY=sk-proj-xxxxxxxx...
    ANTHROPIC_API_KEY=sk-ant-xxxx...
    LOG_LEVEL=INFO
    ```

3.  **Awake Fatih (Build & Run)**
    ```bash
    docker-compose up --build
    ```

## 🛠️ Usage (Planned)

Once running, Fatih will wait for instructions via the CLI entry point.

```python
# Example Workflow
> Fatih, audit target.com
[+] Checking Scope... OK
[+] Starting Recon on target.com...
[+] Found 3 subdomains.
[+] Scanning ports...
...
```
