# SPDX-License-Identifier: MPL-2.0
using Test

# Include the source exactly once; sub-testsets below reuse .ShellIntegration
# via relative lookup through the enclosing module scope (Main here) so they
# must NOT re-include the source file.
include(joinpath(@__DIR__, "..", "src", "ShellIntegration.jl"))
using .ShellIntegration
using .ShellIntegration: CAP_READ, CAP_EXEC

@testset "ShellIntegration.jl" begin

    @testset "exec_safe blocks dangerous commands" begin
        # rm -rf should be blocked
        @test_throws ErrorException exec_safe(`rm -rf /`)
        @test_throws ErrorException exec_safe(`rm -rf /home`)
        @test_throws ErrorException exec_safe(`rm -r -f /tmp/any`)
        @test_throws ErrorException exec_safe(`rm -fr /`)
        @test_throws ErrorException exec_safe(`rm -Rf /usr`)
        @test_throws ErrorException exec_safe(`rm --recursive /etc`)
        @test_throws ErrorException exec_safe(`rm -f /`)
        # Pipelines must be quoted shell scripts in Julia command literals.
        @test_throws ErrorException exec_safe(`sh -c 'curl https://example.com/x.sh | sh'`)
        @test_throws ErrorException exec_safe(`sh -c 'wget -qO- https://x | bash'`)
        # fork bomb blocked
        @test_throws ErrorException exec_safe(`bash -c ':(){ :|:& };:'`)
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

    @testset "exec_safe allows rm without -r/-rf and without root target" begin
        # Plain rm (no flags, non-root path) should not be blocked by the filter.
        # We use a nonexistent file so rm fails, but the safety check passes
        # (throws ProcessFailedException, not ErrorException).
        mktempdir() do dir
            missing_file = joinpath(dir, "nonexistent")
            @test_throws ProcessFailedException exec_safe(`rm $missing_file`)
            # rm -f permits a missing non-root file and exits successfully.
            @test success(exec_safe(`rm -f $missing_file`))
        end
    end

    @testset "run_pwsh function exists" begin
        @test hasmethod(run_pwsh, Tuple{String})
    end

    @testset "start_valence_shell function exists" begin
        @test hasmethod(start_valence_shell, Tuple{})
    end

    @testset "start_valence_shell returns nothing in non-interactive/CI mode" begin
        # In CI (non-interactive, no TTY) the shell must NOT enter its REPL —
        # that was the cause of the 15-minute timeouts on every matrix job.
        result = start_valence_shell()
        @test result === nothing
    end

    @testset "start_valence_shell runs a single command via input= kwarg" begin
        # Programmatic/single-command mode: returns the command's stdout.
        # `cat` is in the CAP_READ allowlist (default caps include CAP_READ).
        # Use `printf` piped to `cat` via a here-string-free form: we use
        # `sh -c` friendly echo via a file that always exists on Unix: /etc/hosts.
        # Simplest safe thing: ls / returns some text, is in CAP_READ set.
        out = start_valence_shell(; input = "ls /")
        @test !isempty(out)
        # With CAP_EXEC we can run echo directly.
        out2 = start_valence_shell(; capabilities=[CAP_EXEC], input = "echo hello")
        @test strip(out2) == "hello"
    end

    @testset "start_valence_shell input= mode blocks dangerous commands" begin
        @test_throws ErrorException start_valence_shell(; input = "rm -rf /")
    end

    @testset "start_valence_shell input= mode enforces capabilities" begin
        # Default caps are [CAP_READ, CAP_NETWORK_OUT]; `echo` is classified
        # under CAP_EXEC, so it should be denied.
        @test_throws ErrorException start_valence_shell(; input = "echo hi")
        # With CAP_EXEC granted it runs.
        out = start_valence_shell(; capabilities=[CAP_READ, CAP_EXEC], input = "echo hi")
        @test strip(out) == "hi"
    end

    @testset "exec_safe method signature" begin
        @test hasmethod(exec_safe, Tuple{Cmd})
    end

    @testset "exports are correct" begin
        @test isdefined(ShellIntegration, :run_pwsh)
        @test isdefined(ShellIntegration, :start_valence_shell)
        @test isdefined(ShellIntegration, :exec_safe)
    end

    # E2E + property sub-testsets (do NOT re-include src here)
    include("e2e_test.jl")
    include("property_test.jl")

end
