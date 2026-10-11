# SPDX-License-Identifier: MPL-2.0
# (MPL-2.0 preferred; MPL-2.0 required for Julia ecosystem)
# Property-based invariant tests for ShellIntegration.jl
#
# IMPORTANT: this file is `include()`d from runtests.jl after the module is
# loaded once. Do NOT re-include src/ShellIntegration.jl or re-declare
# `using .ShellIntegration` here.

using Test
using .ShellIntegration

@testset "Property-Based Tests" begin

    @testset "Invariant: rm -rf* patterns are always blocked" begin
        for path in ["/", "/home", "/boot", "/usr", "/etc", "/var", "/tmp/xyz"]
            @test_throws ErrorException exec_safe(`rm -rf $path`)
        end
    end

    @testset "Invariant: rm -r variants are always blocked" begin
        for path in ["/tmp/a", "/tmp/b", "/var/log"]
            @test_throws ErrorException exec_safe(`rm -r $path`)
            @test_throws ErrorException exec_safe(`rm -Rf $path`)
        end
    end

    @testset "Invariant: rm root target is blocked regardless of flags" begin
        @test_throws ErrorException exec_safe(`rm /`)
        @test_throws ErrorException exec_safe(`rm -f /`)
        @test_throws ErrorException exec_safe(`rm -rf /`)
    end

    @testset "Invariant: safe commands always return a Process" begin
        for cmd in [`echo a`, `echo hello world`, `true`]
            result = exec_safe(cmd)
            @test result isa Base.Process
        end
    end

    @testset "Invariant: start_valence_shell is noninteractive-safe" begin
        # Calling it N times in a loop under CI must not hang; each call
        # returns nothing quickly.
        for _ in 1:10
            @test start_valence_shell() === nothing
            @test start_valence_shell(; noninteractive=true) === nothing
        end
    end

    @testset "Invariant: start_valence_shell input= mode is idempotent" begin
        for _ in 1:5
            # `ls /` is CAP_READ which is in the default capability set.
            @test !isempty(start_valence_shell(; input="ls /"))
        end
    end

    @testset "Invariant: exports are stable across calls" begin
        for _ in 1:20
            @test hasmethod(exec_safe, Tuple{Cmd})
            @test hasmethod(run_pwsh, Tuple{String})
            @test hasmethod(start_valence_shell, Tuple{})
        end
    end

    @testset "Invariant: _is_dangerous is monotonic for known-drawn samples" begin
        # Repeatedly invoking the predicate on the same string must yield
        # the same answer (no state, no RNG).
        dangerous = "rm -rf /"
        safe = "echo hello"
        for _ in 1:100
            @test ShellIntegration._is_dangerous(dangerous)
            @test !ShellIntegration._is_dangerous(safe)
        end
    end

end
