# ADR-0002 — Tool Registry Dual-Dispatch Pattern

**Status:** Accepted  
**Date:** 2026-05-30  
**Deciders:** ktfth

---

## Context

`server.py` must advertise tools to the LLM client (`list_tools()`) and also dispatch calls to handler functions (`_dispatch_tool()`). With 60+ tools, maintaining two independent structures is error-prone — a tool added to one side but not the other either hides from the LLM or crashes at runtime.

Two past failure modes:
- Tool added to `_dispatch_tool` but not `list_tools` → LLM can't call it, silent capability loss
- Tool added to `list_tools` but not `_dispatch_tool` → runtime crash on first call, looks like a server bug

## Decision

Formalize the dual-dispatch pattern with a structural invariant enforced by a test:

1. **`list_tools()`** — advertises tools to the LLM. Returns a list of `Tool` objects with name, description, and input schema.
2. **`_TOOL_REGISTRY` / `_dispatch_tool()`** — maps tool names to handler functions. Dispatch is a single `match` / `dict.get` call.
3. **`TestToolDispatchConsistency`** — a test that statically verifies:
   - Every tool in `list_tools()` is dispatchable in `_dispatch_tool()`
   - Every handler in `_dispatch_tool()` is advertised in `list_tools()`
   - No tool name is duplicated in either direction

### Adding a new tool checklist
1. Add handler function in the appropriate `tools/*.py` module
2. Import handler in `server.py`
3. Add entry to `list_tools()` (name + description + input schema)
4. Add entry to `_TOOL_REGISTRY` mapping name → handler
5. Run `TestToolDispatchConsistency` — fails fast if the two sides drift

## Consequences

**Positive:**
- Drift between advertised and callable tools is caught at test time, not runtime
- Single source of truth for tool names (the registry dict)
- New tools follow a checklist that the consistency test validates

**Negative:**
- Two places to update per new tool (list_tools + registry)
- Test must be updated if the dispatch mechanism changes

**Not considered:**
- Auto-generating `list_tools()` from the registry at runtime. Rejected because tool descriptions and input schemas require human authorship and shouldn't be inferred from function signatures.
