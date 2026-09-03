# Acceptable Use Policy

## Purpose

mxprotector is a research-grade PE binary protector. It is intended for:

- Anti-cheat / DRM / anti-tamper protection of your own software
- Security research (reverse engineering, malware analysis training, protector-evaluation studies)
- CTF / academic study of code virtualization, MBA obfuscation, packer design
- Personal projects where you own the source and the produced binary

## Not acceptable

Use of this software to:

- Obfuscate, pack, or distribute malware (ransomware, credential stealers, botnet nodes, stagers, RATs, cryptominers deployed without owner consent, spyware, etc.)
- Evade endpoint detection & response (EDR), antivirus, or sandbox analysis of third-party targets you do not own or lack written authorization to test
- Break DRM, license enforcement, or copy-protection of software you do not own or lack a license to modify
- Violate the [GitHub Acceptable Use Policies](https://docs.github.com/en/site-policy/acceptable-use-policies)
- Violate applicable law in your jurisdiction

## AV detection

Binaries produced by mxprotector will very likely trigger antivirus heuristics — anti-debug, TLS callbacks, IAT wipe, packed sections, high-entropy strings, and self-decrypting code are all on standard heuristic lists. This is a legitimate cost of the protection technique, not a bug. Do NOT submit protected binaries to VirusTotal or any multi-scanner if you do not want them shared with vendors; VirusTotal shares samples with its partner network.

## Reporting misuse

If you observe mxprotector being used to obfuscate malware in the wild, report it to the relevant AV vendor and, when appropriate, to [GitHub Trust & Safety](https://support.github.com/contact/report-abuse).

## Disclaimer

mxprotector is provided "AS IS" under the MIT license (see LICENSE). The authors accept no liability for how you use it. You are solely responsible for compliance with law and third-party terms.
