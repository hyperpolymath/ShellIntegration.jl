;; SPDX-License-Identifier: PMPL-1.0-or-later
;; ECOSYSTEM.scm for ShellIntegration.jl
;; Media Type: application/vnd.ecosystem+scm

(ecosystem
  (version "1.0")
  (name "ShellIntegration.jl")
  (type "julia-package")
  (purpose "PowerShell integration and capability-restricted shell environment")

  (position-in-ecosystem
    (domain "systems-programming")
    (role "Sandboxed shell execution and PowerShell interoperability")
    (maturity "alpha"))

  (related-projects
    ((name . "hyperpolymath ecosystem")
     (relationship . part-of)
     (nature . "Julia packages for interdisciplinary computing"))))
