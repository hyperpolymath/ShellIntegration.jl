# SPDX-License-Identifier: MPL-2.0
# (MPL-2.0 preferred; MPL-2.0 required for Julia ecosystem)
# BenchmarkTools benchmarks for ShellIntegration.jl

using BenchmarkTools

include(joinpath(@__DIR__, "..", "src", "ShellIntegration.jl"))
using .ShellIntegration

const SUITE = BenchmarkGroup()

SUITE["exec_safe"] = BenchmarkGroup()

SUITE["exec_safe"]["safe_echo"] = @benchmarkable exec_safe(`echo hello`)

SUITE["exec_safe"]["blocked_detection"] = @benchmarkable try
    exec_safe(`rm -rf /`)
catch
end

SUITE["api"] = BenchmarkGroup()

SUITE["api"]["start_valence_shell"] = @benchmarkable start_valence_shell()

SUITE["api"]["method_lookup"] = @benchmarkable begin
    hasmethod(exec_safe, Tuple{Cmd})
    hasmethod(run_pwsh, Tuple{String})
    hasmethod(start_valence_shell, Tuple{})
end

if abspath(PROGRAM_FILE) == @__FILE__
    tune!(SUITE)
    results = run(SUITE, verbose=true)
    BenchmarkTools.save("benchmarks_results.json", results)
end
