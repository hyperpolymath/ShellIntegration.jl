;; SPDX-License-Identifier: PMPL-1.0-or-later
;; STATE.scm for ShellIntegration.jl

(define state
  '((metadata
     (project . "ShellIntegration.jl")
     (version . "0.1.0")
     (updated . "2026-03-10")
     (maintainers . ("Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>")))

    (project-context
     (description . "PowerShell integration and capability-restricted shell environment")
     (domain . "systems-programming")
     (languages . ("Julia"))
     (primary-purpose . "Provide PowerShell interop and sandboxed shell execution from Julia"))

    (current-position
     (phase . "skeleton")
     (overall-completion . 30))

    (blockers-and-issues
     (known-issues . ()))

    (critical-next-actions
     (immediate . ("Implement capability restriction model for shell commands")))))
