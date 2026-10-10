# SPDX-License-Identifier: MPL-2.0
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

Patterns are written to avoid over-blocking: a plain `rm /tmp/...` (no
flags) or `rm -f /tmp/...` (force on a single non-root file) is permitted;
recursive removes (`rm -r`, `rm -rf`, `rm -Rf` …) and any remove that
targets the filesystem root are blocked.
"""
const DANGEROUS_PATTERNS = Regex[
    # --- rm: recursive in any form ---
    # Short -r / -R / --recursive followed by whitespace (may combine with -f etc.)
    r"\brm\s+(?:-[a-zA-Z]*[rR][a-zA-Z]*\s+|--recursive[\s=])",
    # Combined short flags containing both r and f (any order, e.g. -rf, -fr, -Rf, -rvf, -Rfv …)
    r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*[fF][a-zA-Z]*\s",
    r"\brm\s+-[a-zA-Z]*[fF][a-zA-Z]*[rR][a-zA-Z]*\s",
    # Two separate short-flag groups (e.g. `rm -r -f`, `rm -f -R`, `rm -R --force`)
    r"\brm\s+(?:-[a-zA-Z]+|--(?:recursive|force))\s+(?:-[a-zA-Z]+|--(?:recursive|force))\s",
    # --- rm: targeting the filesystem root specifically, with or without -f ---
    r"\brm\s+(?:-[a-zA-ZfFrRv]+\s+)?/\s*(?:$|[;&|>)])",
    # --- other destructive / escalation patterns ---
    r"\bmkfs\.",                                         # format filesystems
    r"\bdd\s+[^|;&>]*of=/dev/",                          # raw device writes
    r"\bchmod\s+(?:-[a-zA-Z]*R[a-zA-Z]*\b|--recursive\b)[^|;&>]*\b777\b",  # world-writable recursion (catches -R, -Rf, -fR, --recursive …)
    r":\(\)\s*\{\s*:\|\s*:\s*&\s*\}\s*;:",               # fork bomb
    r">\s*/dev/sd[a-z]",                                 # overwrite block devices
    r"\bcurl\b[^|;&>]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",     # pipe curl to shell
    r"\bwget\b[^|;&>]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",     # pipe wget to shell
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
                          timeout_seconds::Int = 300,
                          input::Union{AbstractString,Nothing} = nothing,
                          noninteractive::Bool = false)

Start an interactive capability-restricted shell session. Commands are
validated against the granted capability set before execution.

The shell runs in a read-eval-print loop until the user types `exit`,
`quit`, stdin reaches EOF, or the timeout expires.

# Arguments
- `capabilities`: set of granted capabilities (default: read + outbound network)
- `prompt`: the shell prompt string
- `timeout_seconds`: maximum session duration in seconds (default: 300)
- `input`: if provided, run this one command (string) and return its output
  as a `String` instead of entering the interactive REPL. Useful for tests
  and programmatic use.
- `noninteractive`: if `true` (or stdin is not a TTY, or `input` is
  supplied), skip the REPL entirely and return `nothing` immediately when
  there is nothing to execute. This makes the function safe to call from
  automated tests and CI where no TTY is attached.

# Capabilities
- `CAP_READ`: allows `cat`, `ls`, `head`, `tail`, `find`, `grep`
- `CAP_WRITE`: allows `cp`, `mv`, `mkdir`, `touch`, `tee`
- `CAP_NETWORK_OUT`: allows `curl`, `wget`, `ping`, `dig`, `nslookup`
- `CAP_NETWORK_IN`: allows `nc -l`, `python -m http.server`
- `CAP_EXEC`: allows running arbitrary executables
- `CAP_ENV`: allows `env`, `printenv`, `export`

# Returns
- When running interactively: `nothing` (the REPL prints to stdout itself).
- When `input` is supplied: the captured stdout of the command as a `String`.
"""
function start_valence_shell(; capabilities::Vector{Capability} = [CAP_READ, CAP_NETWORK_OUT],
                               prompt::String = "valence> ",
                               timeout_seconds::Int = 300,
                               input::Union{AbstractString,Nothing} = nothing,
                               noninteractive::Bool = false)
    # --- non-interactive fast paths ---
    # 1. Explicit single-command mode (used by tests and programmatic callers).
    if input !== nothing
        return _valence_execute_line(String(input), capabilities)
    end
    # 2. Auto-detect: no TTY and caller didn't pass input -> no-op return.
    #    This is the safety rail that prevents CI from spinning forever
    #    reading from a closed stdin.
    if noninteractive || !(_stdin_is_interactive())
        return nothing
    end

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
            elseif e isa EOFError
                println("\nEnd of input.")
                break
            end
            rethrow(e)
        end

        # readline returns "" at EOF without throwing on some streams
        if !isopen(stdin) || (isempty(line) && eof(stdin))
            println("\nEnd of input.")
            break
        end

        cmd = strip(line)
        isempty(cmd) && continue

        # Built-in commands
        if cmd in ("exit", "quit")
            println("Valence Shell closed.")
            break
        elseif cmd == "help"
            _valence_help(capabilities)
            continue
        elseif cmd == "caps"
            println("Active capabilities: [$cap_names]")
            continue
        elseif cmd == "elapsed"
            println("Session time: $(round(elapsed; digits=1))s / $(timeout_seconds)s")
            continue
        end

        _valence_handle_command(cmd, capabilities)
    end
    return nothing
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
    # Inspect argument text without display backticks/quotes, which can hide
    # end-of-command matches such as the root target in `rm -f /`.
    cmd_str = join(cmd, " ")
    if _is_dangerous(cmd_str)
        error("Unsafe command blocked: $cmd_str")
    end
    return run(cmd)
end

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

"""Check whether stdin looks like an interactive TTY. Returns false in CI
and other non-interactive contexts (e.g., when a test calls us without
mocking stdin, or when a parent process piped in nothing)."""
function _stdin_is_interactive()
    # `isinteractive()` is Julia's global flag, true on a REPL/-i; false
    # under `julia -e`, `julia script.jl`, and `Pkg.test()` (which runs via
    # `-e`). We additionally require stdin to be an actual TTY handle so
    # that piped input (`echo | julia`) still works as a batch.
    try
        return isinteractive() && stdin isa Base.TTY
    catch
        return false
    end
end

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

"""Execute a single line from the Valence shell: safety-check, capability-
check, then run via `sh -c`. Returns the captured stdout as a String
(used by the `input=` path); the interactive path uses
`_valence_handle_command` which prints to stdout."""
function _valence_execute_line(cmd::String, caps::Vector{Capability})::String
    # Safety check: block dangerous patterns unconditionally
    if _is_dangerous(cmd)
        error("BLOCKED: Command matches a dangerous pattern: $cmd")
    end
    # Capability check
    if !_has_capability(cmd, caps)
        error("DENIED: Insufficient capabilities for command: $cmd")
    end
    return read(`sh -c $cmd`, String)
end

"""Interactive-mode helper: run the safety/capability checks and execute,
printing results or errors to stdout (no thrown exceptions to the REPL)."""
function _valence_handle_command(cmd::String, caps::Vector{Capability})
    if _is_dangerous(cmd)
        println("BLOCKED: Command matches a dangerous pattern.")
        return
    end
    if !_has_capability(cmd, caps)
        cap_names = join(string.(caps), ", ")
        println("DENIED: Insufficient capabilities for this command.")
        println("  Granted: [$cap_names]")
        return
    end
    try
        result = read(`sh -c $cmd`, String)
        isempty(result) || print(result)
    catch e
        println("Error: $(sprint(showerror, e))")
    end
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
