# SPDX-License-Identifier: MPL-2.0
# (MPL-2.0 preferred; MPL-2.0 required for Julia ecosystem)
# Property-based invariant tests for ShellIntegration.jl

using Test

include(joinpath(@__DIR__, "..", "src", "ShellIntegration.jl"))
using .ShellIntegration

@testset "Property-Based Tests" begin

    @testset "Invariant: rm -rf* patterns are always blocked" begin
        # Any command starting with rm and containing -rf must be blocked
        for path in ["/", "/home", "/boot", "/usr", "/etc", "/var"]
            @test_throws ErrorException exec_safe(`rm -rf $path`)
        end
    end

    @testset "Invariant: safe commands always return a Process" begin
        # Various safe shell commands
        for cmd in [`echo a`, `echo hello world`, `true`]
            result = exec_safe(cmd)
            @test result isa Base.Process
        end
    end

    @testset "Invariant: start_valence_shell always returns nothing" begin
        for _ in 1:10
            @test start_valence_shell() === nothing
        end
    end

    @testset "Invariant: exports are stable across calls" begin
        for _ in 1:20
            @test hasmethod(exec_safe, Tuple{Cmd})
            @test hasmethod(run_pwsh, Tuple{String})
            @test hasmethod(start_valence_shell, Tuple{})
        end
    end

end
