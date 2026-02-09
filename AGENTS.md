# AGENTS.md

This repository **does not implement agents**.

This file exists to explicitly document the boundary between **Provenact** and any future or external agent systems, and to prevent scope creep inside the core execution substrate.

---

## What This Repo Is

**Provenact** is a secure execution substrate for:

- immutable executables (“skills”)
- explicit capability enforcement
- cryptographic provenance
- deterministic, auditable execution

It answers questions like:
- What is this artifact?
- Who signed it?
- What capabilities does it declare?
- Is it allowed to run?
- What exactly happened when it ran?

---

## What This Repo Is NOT

This repository intentionally does **not** include:

- agent loops
- planners
- schedulers
- workflow engines
- LLM integrations
- tool-selection logic
- long‑lived memory systems
- autonomous decision-making

If you are looking for an *agent framework*, you are in the wrong repo.

---

## Definitions

### Skill
An immutable, attestable executable artifact (initially WASM) with:
- a manifest declaring capabilities
- reproducible builds
- deterministic behavior (unless explicitly scoped otherwise)

### Agent
A higher-level system that:
- maintains state over time
- makes decisions about *what to do next*
- invokes skills/tools as part of a loop
- may include nondeterministic components

Agents are **compositions built on top of Provenact**, not part of it.

---

## The Boundary (Non‑Negotiable)

Provenact provides **safe execution**.

Agents provide **decision-making and orchestration**.

These must remain separate because agents:
- expand the threat surface
- obscure auditability
- introduce nondeterminism
- blur capability boundaries

Any feature proposal that introduces “agency” belongs in a **different project**.

---

## What Provenact May Support (Agent‑Adjacent Only)

Provenact may support the *needs of agents* only insofar as they improve safe execution:

- strict tool isolation
- capability-limited I/O
- execution receipts (inputs, outputs, hashes)
- explicit time / randomness capabilities
- composable skills without privilege propagation

This is about **tools**, not autonomy.

---

## Design Smell Test

If a proposed change answers any of the following, it probably does NOT belong here:

- “How does it decide what to do next?”
- “How does it plan?”
- “Where does it store memory?”
- “How does it browse the web?”
- “How does it schedule tasks?”

Provenact should instead answer:

- “What ran?”
- “Under what authority?”
- “With which capabilities?”
- “With what inputs and outputs?”

---

## Recommended Layering

A sane architecture:

1. **Provenact (this repo)**
   - packaging
   - signing
   - verification
   - sandboxed execution

2. **Skills / Tools**
   - blessed stdlib skills (in-repo)
   - third-party skills (out-of-repo)

3. **Agent Systems (separate repos)**
   - orchestration
   - planning
   - state management
   - UI / HITL

---

## One‑Line Rule

**Provenact executes verified skills. Agents live elsewhere.**

---

If you are adding code to this repository, assume this file is binding.
