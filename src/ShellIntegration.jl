# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# ShellIntegration.jl - Safe shell execution with capability restrictions.

module ShellIntegration

export run_pwsh, start_valence_shell, exec_safe

# Capability flags for the Valence restricted shell
@enum Capability begin
    CAP_READ          # Read filesystem
    CAP_WRITE         # Write filesystem
    CAP_NETWORK_OUT   # Outbound network
    CAP_NETWORK_IN    # Inbound network (listen)
    CAP_EXEC          # Execute subprocesses
    CAP_ENV           # Access environment variables
end

"""
    DANGEROUS_PATTERNS

Shell command patterns that are unconditionally blocked regardless of
capabilities. These patterns represent destructive or privilege-escalation
commands that should never be executed from an automated shell.
"""
const DANGEROUS_PATTERNS = [
    r"rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?/",        # rm -rf / or rm -f /path
    r"rm\s+-rf\s",                                  # rm -rf anything
    r"mkfs\.",                                       # format filesystems
    r"dd\s+.*of=/dev/",                             # raw device writes
    r"chmod\s+-R\s+777",                             # world-writable recursion
    r":(){ :\|:& };:",                              # fork bomb
    r">\s*/dev/sd[a-z]",                            # overwrite block devices
    r"curl.*\|\s*(ba)?sh",                          # pipe curl to shell
    r"wget.*\|\s*(ba)?sh",                          # pipe wget to shell
]

"""
    run_pwsh(script::String) -> String

Execute a PowerShell Core (pwsh) script and return its standard output.
Requires `pwsh` to be available in the system PATH.

# Arguments
- `script`: the PowerShell script text to execute

# Returns
Standard output of the script as a String.

# Throws
- `ErrorException` if pwsh is not found or the script fails.
"""
function run_pwsh(script::String)
    cmd = `pwsh -NoProfile -NonInteractive -Command $script`
    return read(cmd, String)
end

"""
    start_valence_shell(; capabilities::Vector{Capability} = [CAP_READ, CAP_NETWORK_OUT],
                          prompt::String = "valence> ",
                          timeout_seconds::Int = 300)

Start an interactive capability-restricted shell session. Commands are
validated against the granted capability set before execution.

The shell runs in a read-eval-print loop until the user types `exit`,
`quit`, or the timeout expires.

# Arguments
- `capabilities`: set of granted capabilities (default: read + outbound network)
- `prompt`: the shell prompt string
- `timeout_seconds`: maximum session duration in seconds (default: 300)

# Capabilities
- `CAP_READ`: allows `cat`, `ls`, `head`, `tail`, `find`, `grep`
- `CAP_WRITE`: allows `cp`, `mv`, `mkdir`, `touch`, `tee`
- `CAP_NETWORK_OUT`: allows `curl`, `wget`, `ping`, `dig`, `nslookup`
- `CAP_NETWORK_IN`: allows `nc -l`, `python -m http.server`
- `CAP_EXEC`: allows running arbitrary executables
- `CAP_ENV`: allows `env`, `printenv`, `export`
"""
function start_valence_shell(; capabilities::Vector{Capability} = [CAP_READ, CAP_NETWORK_OUT],
                               prompt::String = "valence> ",
                               timeout_seconds::Int = 300)
    cap_names = join(string.(capabilities), ", ")
    println("Valence Shell Active")
    println("  Capabilities: [$cap_names]")
    println("  Timeout: $(timeout_seconds)s")
    println("  Type 'help' for commands, 'exit' to quit.")
    println()

    start_time = time()

    while true
        # Check timeout
        elapsed = time() - start_time
        if elapsed >= timeout_seconds
            println("\nSession timed out after $(timeout_seconds)s.")
            break
        end

        # Read input
        print(prompt)
        flush(stdout)
        line = try
            readline(stdin)
        catch e
            if e isa InterruptException
                println("\nInterrupted.")
                break
            end
            rethrow(e)
        end

        input = strip(line)
        isempty(input) && continue

        # Built-in commands
        if input in ("exit", "quit")
            println("Valence Shell closed.")
            break
        elseif input == "help"
            _valence_help(capabilities)
            continue
        elseif input == "caps"
            println("Active capabilities: [$cap_names]")
            continue
        elseif input == "elapsed"
            println("Session time: $(round(elapsed; digits=1))s / $(timeout_seconds)s")
            continue
        end

        # Safety check: block dangerous patterns unconditionally
        if _is_dangerous(input)
            println("BLOCKED: Command matches a dangerous pattern.")
            continue
        end

        # Capability check
        if !_has_capability(input, capabilities)
            println("DENIED: Insufficient capabilities for this command.")
            println("  Granted: [$cap_names]")
            continue
        end

        # Execute
        try
            result = read(`sh -c $input`, String)
            isempty(result) || print(result)
        catch e
            println("Error: $(sprint(showerror, e))")
        end
    end
end

"""
    exec_safe(cmd::Cmd) -> Base.Process

Execute a system command after validating it against dangerous patterns.
Blocks known destructive commands (rm -rf, mkfs, dd to devices, fork bombs,
and piping downloads to shell).

# Throws
- `ErrorException` if the command matches a dangerous pattern.
"""
function exec_safe(cmd::Cmd)
    cmd_str = string(cmd)
    if _is_dangerous(cmd_str)
        error("Unsafe command blocked: $cmd_str")
    end
    return run(cmd)
end

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

"""Check whether a command string matches any dangerous pattern."""
function _is_dangerous(cmd_str::String)
    for pattern in DANGEROUS_PATTERNS
        if occursin(pattern, cmd_str)
            return true
        end
    end
    return false
end

"""
Determine whether the given command is permitted under the active capability set.
Commands are classified by their first token (the executable name).
"""
function _has_capability(input::String, caps::Vector{Capability})
    tokens = split(input)
    isempty(tokens) && return true
    exe = lowercase(String(tokens[1]))

    # Read-only filesystem commands
    read_cmds = Set(["cat", "ls", "head", "tail", "find", "grep", "rg",
                      "wc", "file", "stat", "du", "df", "less", "more",
                      "realpath", "readlink", "sha256sum", "md5sum"])
    if exe in read_cmds
        return CAP_READ in caps
    end

    # Write filesystem commands
    write_cmds = Set(["cp", "mv", "mkdir", "touch", "tee", "chmod",
                       "chown", "truncate", "install"])
    if exe in write_cmds
        return CAP_WRITE in caps
    end

    # Outbound network commands
    net_out_cmds = Set(["curl", "wget", "ping", "dig", "nslookup",
                         "host", "traceroute", "ssh", "scp", "rsync"])
    if exe in net_out_cmds
        return CAP_NETWORK_OUT in caps
    end

    # Inbound network (listening)
    if exe in Set(["nc", "ncat", "socat"])
        # Listening requires NETWORK_IN, connecting requires NETWORK_OUT
        if any(t -> t in ["-l", "--listen"], tokens)
            return CAP_NETWORK_IN in caps
        end
        return CAP_NETWORK_OUT in caps
    end

    # Environment access
    env_cmds = Set(["env", "printenv", "export"])
    if exe in env_cmds
        return CAP_ENV in caps
    end

    # General execution: anything not classified above requires CAP_EXEC
    return CAP_EXEC in caps
end

"""Print help text for the Valence shell."""
function _valence_help(caps::Vector{Capability})
    println("Valence Shell - Capability-Restricted Environment")
    println()
    println("Built-in commands:")
    println("  help     - Show this help")
    println("  caps     - Show active capabilities")
    println("  elapsed  - Show session time")
    println("  exit     - Close the shell")
    println()
    println("Active capabilities:")
    for cap in caps
        cmds = if cap == CAP_READ
            "cat, ls, head, tail, find, grep, wc, file, stat"
        elseif cap == CAP_WRITE
            "cp, mv, mkdir, touch, tee, chmod"
        elseif cap == CAP_NETWORK_OUT
            "curl, wget, ping, dig, ssh, scp"
        elseif cap == CAP_NETWORK_IN
            "nc -l, socat (listen mode)"
        elseif cap == CAP_EXEC
            "any executable"
        elseif cap == CAP_ENV
            "env, printenv, export"
        else
            "(unknown)"
        end
        println("  $(cap): $cmds")
    end
end

end # module
