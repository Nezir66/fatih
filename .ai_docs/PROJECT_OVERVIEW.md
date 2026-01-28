# 🚀 Project Fatih - Context & Tech Stack

## 1. What does this project do?

**Project Fatih** is an autonomous, LLM-driven **Penetration Testing Agent** designed to audit SaaS applications. It mimics the behavior of a human "Junior Blue/Purple Teamer".

### Core Philosophy

- **Name Origin:** "Fatih" (The Conqueror) – Symbolizes finding unconventional paths to conquer impossible targets.
- **Methodology:** It uses the **ReAct Pattern** (Reason + Act). The AI doesn't just run a script; it:
  1.  **Observes** the target (Recon).
  2.  **Reasons** about the findings (e.g., "Port 80 is open, I should check for HTTP vulnerabilities").
  3.  **Acts** by calling specific tools via Python wrappers.
  4.  **Loops** until the goal is met or time runs out.

### Key Capabilities

- **Scope Enforcement:** Strictly adheres to allowed domains (Safety Layer).
- **Tool Orchestration:** Runs CLI tools inside a secure Docker container.
- **State Management:** Maintains a persistent memory of found IPs, URLs, and vulnerabilities across the session.
- **Non-Destructive:** Focuses on detection, not exploitation (PoC only).

---

## 2. Technology Stack

### A. Infrastructure (The Body)

- **OS:** Debian Bookworm (Stable LTS)
- **Containerization:** Docker & Docker Compose.

### B. Core Logic (The Nervous System)

- **Language:** Python 3.11+.
- **Libraries:**
  - `openai` / `anthropic`: For LLM communication.
  - `pydantic`: For strict data validation and schema generation (State Management).
  - `requests`: For HTTP interaction.

### C. The Arsenal (Security Tools)

We prioritize **Go-based** modern tools for speed and JSON output capabilities:

1.  **Nuclei:** Template-based vulnerability scanner (Primary weapon).
2.  **Subfinder:** Passive subdomain enumeration.
3.  **Naabu:** Fast port scanner.
4.  **Httpx:** Web server probing & technology detection.
5.  **Nmap:** Deep service inspection (Secondary weapon).

### D. The Brain (Decision Layer)

- **Models:** GPT or Claude.
- **Mechanism:** Native Function Calling (Tool use).
