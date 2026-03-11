# SPDX-License-Identifier: PMPL-1.0-or-later
using Test

include(joinpath(@__DIR__, "..", "src", "ShellIntegration.jl"))
using .ShellIntegration

@testset "ShellIntegration.jl" begin

    @testset "exec_safe blocks dangerous commands" begin
        # rm -rf should be blocked
        @test_throws ErrorException exec_safe(`rm -rf /`)
        @test_throws ErrorException exec_safe(`rm -rf /home`)
        # Verify the error message is informative
        try
            exec_safe(`rm -rf /tmp/test`)
            @test false  # Should not reach here
        catch e
            @test e isa ErrorException
            @test contains(e.msg, "Unsafe command blocked")
        end
    end

    @testset "exec_safe allows safe commands" begin
        # echo is safe and should succeed
        result = exec_safe(`echo hello`)
        @test result isa Base.Process
    end

    @testset "exec_safe allows rm without -rf" begin
        # Plain rm (without -rf) should not be blocked by the filter
        # We use a nonexistent file so rm fails, but the safety check passes
        @test_throws ProcessFailedException exec_safe(`rm /tmp/nonexistent_file_shellintegration_test_99`)
    end

    @testset "run_pwsh function exists" begin
        @test hasmethod(run_pwsh, Tuple{String})
    end

    @testset "start_valence_shell function exists" begin
        @test hasmethod(start_valence_shell, Tuple{})
    end

    @testset "start_valence_shell returns nothing" begin
        # The stub just prints and returns nothing
        result = start_valence_shell()
        @test result === nothing
    end

    @testset "exec_safe method signature" begin
        @test hasmethod(exec_safe, Tuple{Cmd})
    end

    @testset "exports are correct" begin
        @test isdefined(ShellIntegration, :run_pwsh)
        @test isdefined(ShellIntegration, :start_valence_shell)
        @test isdefined(ShellIntegration, :exec_safe)
    end

end
