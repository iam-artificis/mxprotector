# Security policy for mxprotector

## Supported versions
The project is currently pre-1.0 research software. Only the `master` branch tip is supported for security fixes.

## Reporting a vulnerability
mxprotector reads and rewrites PE binary input supplied by the user. Vulnerabilities that could allow a malicious input PE to execute code inside the builder, corrupt the file system, or exfiltrate data are in scope. Please report them privately:

- **Preferred**: use GitHub's private vulnerability reporting for this repo (Security tab → Report a vulnerability).
- **Fallback**: open a GitHub issue with the label `security` and NO exploit details; a maintainer will follow up with a private channel.

Please do NOT open a public issue with reproduction steps for a real vulnerability.

Include: affected commit SHA, input PE (or minimal reproducer), observed behavior, expected behavior, your environment (OS, compiler, CMake version).

## Response expectations
This is a research project maintained on best-effort. Aim for acknowledgement within 7 days and a fix or triage within 30 days. Severity is judged by realistic attacker capability, not theoretical impact.

## Out of scope
- The fact that binaries produced by mxprotector trigger antivirus heuristics — that is expected behavior of the protection techniques (see ACCEPTABLE_USE.md).
- Anti-analysis code inside the runtime stubs being reverse-engineered — the tool is a research artifact; the stubs are not obfuscation warranties.
- Bugs that require running an already-compromised build environment.
