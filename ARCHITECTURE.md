# 🏛️ Fatih Architecture & Process Flow

This document visualizes how the **Fatih AI Agent** operates, thinks, and executes attacks.

## The Conquest Loop (ReAct Pattern)

The system is designed as an infinite loop of **Reasoning** and **Acting**, controlled by the central State Manager.

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
