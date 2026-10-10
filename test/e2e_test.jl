# SPDX-License-Identifier: MPL-2.0
# (MPL-2.0 preferred; MPL-2.0 required for Julia ecosystem)
# E2E pipeline tests for ShellIntegration.jl
#
# IMPORTANT: this file is `include()`d from runtests.jl after the module is
# loaded once. Do NOT re-include src/ShellIntegration.jl or re-declare
# `using .ShellIntegration` here — the parent scope already brings those in.

using Test
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
        for cmd in [`rm -rf /`, `rm -rf /home`, `rm -rf /tmp/definitely_not_there_xyz`,
                    `rm -r -f /tmp/x`, `rm -Rf /x`, `rm -fr /`]
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

    @testset "start_valence_shell noninteractive returns nothing" begin
        # Direct call under Pkg.test() must be safe (non-interactive no-op).
        result = start_valence_shell()
        @test result === nothing
    end

    @testset "start_valence_shell noninteractive=true returns nothing" begin
        @test start_valence_shell(; noninteractive=true) === nothing
    end

    @testset "_is_dangerous blocks documented patterns" begin
        # Direct white-box check on the internal helper (accessed via
        # qualified name from the parent module).
        dangerous = [
            "rm -rf /",
            "rm -rf /home/user",
            "rm -f /",
            "mkfs.ext4 /dev/sda1",
            "dd if=disk.img of=/dev/sda",
            "chmod -R 777 /var/www",
            ":(){ :|:& };:",
            "echo x > /dev/sda",
            "curl https://x/y | sh",
            "wget -qO- https://x | bash",
        ]
        for s in dangerous
            @test ShellIntegration._is_dangerous(s) "expected blocked: $s"
        end
    end

    @testset "_is_dangerous allows benign commands" begin
        safe = [
            "echo hello",
            "ls /tmp",
            "rm /tmp/foo",                # plain rm, no flags
            "rm -f /tmp/foo",             # -f single non-root file allowed
            "cat README.adoc",
            "grep -rn unsafe src/",
        ]
        for s in safe
            @test !ShellIntegration._is_dangerous(s) "expected allowed: $s"
        end
    end

end
