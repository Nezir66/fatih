# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Fatih** is an LLM-driven autonomous penetration testing agent designed for SaaS security auditing. The project uses a ReAct pattern (Observe → Orient → Decide → Act) to intelligently interact with web applications and identify vulnerabilities that traditional scanners miss.

**Security Context:** This is a defensive security tool (Blue/Purple Team). Only work on authorized targets. The agent identifies vulnerabilities for hardening purposes, never for exploitation.

## Architecture

The system follows a "Brain/Body" metaphor:

- **The Brain**: OpenAI/Claude LLM that decides strategy and analyzes results
- **The Body**: Docker container that executes security tools in isolation
- **The Nervous System**: Python orchestration layer that bridges the LLM and tools
- **The Arsenal**: CLI security tools (Nmap, Nuclei, Subfinder, Naabu, Httpx, Katana)

### Directory Structure

```
src/
  core/           # Orchestrator, state manager, security controls
  llm/            # LLM client and prompt templates
  tools/          # Tool wrappers and definitions
    network/      # Nmap, Naabu
    web/          # Nuclei, Httpx, Katana
  utils/          # Parsers, logging
config/           # settings.yaml, tools_config.yaml
docker/           # Dockerfile and scripts for Debian Bookworm container
tests/            # Test suite
outputs/          # Generated reports and scan results
```

## Development Commands

### Environment Setup

```bash
# Create .env with API keys
OPENAI_API_KEY=sk-proj-...
ANTHROPIC_API_KEY=sk-ant-...
LOG_LEVEL=INFO
```

### Running the Agent

```bash
# Build and start the Docker environment
docker-compose up --build

# Run main entry point
python main.py
```

## Key Architectural Patterns

### ReAct Loop (Reasoning & Acting)

The orchestrator implements a continuous loop:

1. **Observe**: Parse tool outputs
2. **Orient**: LLM analyzes current state
3. **Decide**: LLM chooses next action
4. **Act**: Execute selected tool in Docker container

### Tool Execution Flow

1. `orchestrator.py` receives command from LLM
2. Security validation via `security.py` (scope checking, command sanitization)
3. Tool wrapper (e.g., `tools/network/nmap.py`) formats the command
4. Execution happens inside Docker container
5. `utils/parsers.py` processes raw output into structured data
6. Results fed back to LLM via `llm/client.py`

### State Management

`state_manager.py` maintains:

- Discovered assets (subdomains, ports, endpoints)
- Scan history to avoid redundant operations
- Findings and vulnerability database

## Design Principles

1. **Context-Aware Scanning**: The LLM understands what a service is before attacking it, reducing noise and false positives.

2. **Non-Destructive**: Identify vulnerabilities without causing DoS or data deletion.

3. **Docker Isolation**: All tool execution happens in a sandboxed container to prevent host contamination.

4. **Scope Enforcement**: `security.py` ensures all operations stay within authorized boundaries.

## Success Criteria

The agent should autonomously:

1. Create a step-by-step audit plan for a given URL
2. Execute CLI tools and gather data
3. Interpret tool output and decide next moves
4. Generate actionable vulnerability reports

## Phase Roadmap

- **Phase 1 (Deep Reconnaissance)**: Surface mapping with Subfinder, Naabu, Httpx
- **Phase 2 (Precision Scanning)**: CVE/misconfiguration detection with Nuclei, Nmap
- **Phase 3 (Logic & Reasoning)**: Business logic flaws via LLM analysis (IDOR, privilege escalation)
