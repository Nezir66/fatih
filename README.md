<div align="center">

<img src="assets/images/logo.jpeg" alt="Fatih Logo" width="300"/>

# F A T I H

**The Autonomous AI Penetration Testing Agent**

[![Status](https://img.shields.io/badge/Status-Development-yellow)](https://github.com/Nezir66/fatih)
[![Docker](https://img.shields.io/badge/Docker-Debian_Bookworm-blue)](https://www.docker.com/)
[![AI](https://img.shields.io/badge/AI-LLM_Powered-purple)](https://openai.com/)

---

</div>

## 🎯 What is Fatih?

**Fatih** is an autonomous AI agent designed to perform comprehensive security audits on web applications. Unlike traditional scanners that simply list vulnerabilities, Fatih uses a **Reasoning Loop** (Observe → Orient → Decide → Act) to intelligently explore, analyze, and validate findings.

It runs in a secure, isolated **Docker** environment ("The Body") controlled by a powerful Cloud AI ("The Brain"), bridging the gap between static analysis and human-like penetration testing.

## ✨ Features

- **🧠 Autonomous Reasoning Engine**: Built on the ReAct pattern, Fatih creates dynamic plans, executes tools, and adapts its strategy based on real-time feedback.
- **🛡️ Secure Isolation**: All dangerous operations run inside a sandboxed Docker container (Debian Bookworm), keeping your host system safe.
- **🔍 Deep Reconnaissance**:
  - **Subdomain Discovery**: Integrated with **Subfinder** to map attack surfaces.
  - **Port Scanning**: intelligent **Nmap** execution to identify open services.
  - **Web Crawling**: Uses **Katana** and **Httpx** for deep endpoint discovery and technology stack detection.
  - **Fuzzing**: Directory and file brute-forcing with **ffuf**.
- **💾 State Management**: Persistent memory of hosts, ports, and vulnerabilities across sessions.

## 🏗️ Architecture

Fatih emulates a human penetration tester's methodology using a sophisticated agentic architecture.

```mermaid
graph TD
    %% --- Styles ---
    classDef brain fill:#f9f,stroke:#333,stroke-width:2px,color:black;
    classDef body fill:#bbf,stroke:#333,stroke-width:2px,color:black;
    classDef tools fill:#dfd,stroke:#333,stroke-width:2px,color:black;
    classDef ext fill:#ddd,stroke:#333,stroke-width:4px,color:black;

    %% --- Actors ---
    User([👤 User / Admin])
    Target(🌐 Target SaaS):::ext

    %% --- The System ---
    subgraph "Fatih Container (The Body)"
        Entry[🏁 main.py]

        subgraph "Core Logic"
            Orchestrator{⚙️ Orchestrator}:::body
            ScopeGuard[🛡️ Scope Guard]:::body
            StateManager[(💽 State / Memory)]:::body
        end

        subgraph "Tool Execution Layer"
            ToolWrapper[🔧 Python Tool Wrapper]:::body
            Shell[>_ Bash / Docker Shell]:::tools
            Parser[🧹 Output Parser]:::body
        end
    end

    subgraph "Cloud (The Brain)"
        LLM[🧠 GPT-5.1 / Claude 3.5]:::brain
    end

    %% --- The Flow ---
    User --> |"Audit target.com"| Entry
    Entry --> ScopeGuard
    ScopeGuard -- "Denied" --> User
    ScopeGuard -- "Approved" --> Orchestrator

    %% The Loop
    Orchestrator --> |"1. Get Context + History"| StateManager
    StateManager --> |"2. Current Knowledge"| Orchestrator
    Orchestrator --> |"3. Send Prompt + Schema"| LLM

    LLM --> |"4. Decision: Function Call"| Orchestrator

    Orchestrator -- "If Tool Call" --> ToolWrapper
    Orchestrator -- "If Analysis/Final" --> User

    ToolWrapper --> |"5. Build Command"| Shell
    Shell --> |"6. Execute Binary"| Target
    Target --> |"7. Raw Result (XML/JSON)"| Shell
    Shell --> |"8. Raw Output"| Parser
    Parser --> |"9. Cleaned JSON"| Orchestrator

    Orchestrator --> |"10. Update Knowledge"| StateManager

    %% Loop back
    StateManager -.-> |"Loop continues..."| Orchestrator
```

## 🚀 Getting Started

### Prerequisites

- **Docker & Docker Compose**
- **API Key** (OpenAI or Anthropic)

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
    anthropic_api_key=sk-ant-xxxx...
    LOG_LEVEL=INFO
    ```

3.  **Awake Fatih (Build & Run)**

    ```bash
    docker-compose up --build
    ```

## 🛠️ Usage

Once running, Fatih will wait for instructions via the CLI entry point.

```bash
# Example Workflow
> Fatih, audit target.com
[+] Checking Scope... OK
[+] Starting Recon on target.com...
[+] Found 3 subdomains.
[+] Scanning ports...
...
```

## ⚠️ Disclaimers

### Important Usage Guidelines

**1. Potential for Mutative Effects**
This is not a passive scanner. Fatih is designed to **actively interact** with the target. This process can have mutative effects (e.g., submitting forms, triggering alerts).

**2. Legal & Ethical Use**
Fatih is designed for legitimate security auditing purposes only.

> [!CAUTION]
> **You must have explicit, written authorization** from the owner of the target system before running Fatih.
>
> Unauthorized scanning and exploitation of systems you do not own is illegal. The maintainers are not responsible for any misuse of this tool.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

<p align="center">
  <b>Built with ❤️ by Nezir66</b><br>
  <i>Empowering Security through Autonomous AI</i>
</p>
