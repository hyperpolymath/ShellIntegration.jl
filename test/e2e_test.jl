# SPDX-License-Identifier: MPL-2.0
# (MPL-2.0 preferred; MPL-2.0 required for Julia ecosystem)
# E2E pipeline tests for ShellIntegration.jl

using Test

include(joinpath(@__DIR__, "..", "src", "ShellIntegration.jl"))
using .ShellIntegration

@testset "E2E Pipeline Tests" begin

    @testset "Safe command execution pipeline" begin
        # Run a safe command and verify it succeeds
        result = exec_safe(`echo hello`)
        @test result isa Base.Process
        @test success(result)
    end

    @testset "Dangerous command is blocked" begin
        # Each dangerous rm -rf variant must be blocked
        for cmd in [`rm -rf /`, `rm -rf /home`, `rm -rf /tmp/definitely_not_there_xyz`]
            @test_throws ErrorException exec_safe(cmd)
        end
    end

    @testset "exec_safe error message is informative" begin
        try
            exec_safe(`rm -rf /tmp/test_shellintegration`)
            @test false  # Must not reach here
        catch e
            @test e isa ErrorException
            @test occursin("Unsafe command blocked", e.msg)
        end
    end

    @testset "start_valence_shell does not crash" begin
        result = start_valence_shell()
        @test result === nothing
    end

end
