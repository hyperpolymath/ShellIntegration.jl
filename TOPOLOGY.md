<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->
<!-- TOPOLOGY.md — Project architecture map and completion dashboard -->
<!-- Last updated: 2026-02-19 -->

# ShellIntegration.jl — Project Topology

## System Architecture

```
                        ┌─────────────────────────────────────────┐
                        │          OPERATING SYSTEM / SHELLS      │
                        ├─────────────────────────────────────────┤
                        │  ┌────────────┐      ┌────────────┐     │
                        │  │ PowerShell │ ◀──▶ │ Bash/Zsh   │     │
                        │  │ (pwsh)     │      │ (Standard) │     │
                        │  └─────▲──────┘      └─────▲──────┘     │
                        │        │                   │            │
                        └────────┼───────────────────┼────────────┘
                                 │                   │
                                 ▼                   │
                        ┌────────────────────────────┼────────────┐
                        │           INTEGRATION LAYER             │
                        ├─────────────────────────────────────────┤
                        │  ┌──────────────────┐      ┌──────────┐ │
                        │  │ PowerShell Bridge│      │ Valence  │ │
                        │  │   (run_pwsh)     │ ───▶ │ Shell    │ │
                        │  └────────┬─────────┘      └─────┬────┘ │
                        │           │                      │      │
                        │  ┌────────▼─────────┐      ┌─────▼────┐ │
                        │  │   Safety         │      │ Capability│ │
                        │  │   Wrappers       │ ◀──▶ │ System    │ │
                        │  └──────────────────┘      └──────────┘ │
                        └──────────────────────┬──────────────────┘
                                               │
                        ┌──────────────────────▼──────────────────┐
                        │         REPO INFRASTRUCTURE             │
                        │  .github/workflows/ (RSR Gate)          │
                        │  Project.toml                           │
                        └─────────────────────────────────────────┘
```

## Completion Dashboard

```
COMPONENT                          STATUS              NOTES
─────────────────────────────────  ──────────────────  ─────────────────────────────────
CORE INTEGRATION
  PowerShell Bridge                 ██████████ 100%    Basic pwsh execution working
  Valence Shell                     ██░░░░░░░░  20%    Stub implementation
  Safety Wrappers                   ██████████ 100%    Basic command blocking

FEATURES
  Capability System                 ░░░░░░░░░░   0%    Planned
  Secure Environment                ░░░░░░░░░░   0%    Planned
  Cross-Platform Admin              ██████░░░░  60%    Basic scripts functional

REPO INFRASTRUCTURE
  .github/workflows/ (CI)           ██████████ 100%    RSR standard compliance

─────────────────────────────────────────────────────────────────────────────
OVERALL:                            ██░░░░░░░░  ~25%   Initial Bridge Scaffold
```

## Key Dependencies

```
OS Shells ───────────► Bridge Logic ───────────► Unified API
                            ▲                      │
Safety Wrappers ────────────┘                      ▼
                                             Secure Shell (Valence)
```

## Update Protocol

This file is maintained by both humans and AI agents. When updating:

1. **After completing a component**: Change its bar and percentage
2. **After adding a component**: Add a new row in the appropriate section
3. **After architectural changes**: Update the ASCII diagram
4. **Date**: Update the `Last updated` comment at the top of this file

Progress bars use: `█` (filled) and `░` (empty), 10 characters wide.
Percentages: 0%, 10%, 20%, ... 100% (in 10% increments).
