# smapper

is a lightweight, high‑accuracy asset discovery & subdomain enumeration tool.
Part of the **Phantom Sight** framework (our in‑house adversary emulation / continuous recon platform).

> **Note:** this repository contains the standalone `smapper` tool. If you'd like to collaborate, I’m sharing access to our private Discord channel for early adopters — **first 1 member only (unless you contribute)**. See **Community / Contact** below.

---

## What is smapper?

`smapper` is a focused, pragmatic tool for discovering and validating subdomains and related assets with maximum coverage and minimal noise. It combines CRT/CT, passive sources, DNS validation, and lightweight resolution checks into a fast, reliable pipeline suitable for recon workflows, bug bounty triage, and offensive security engagements.

Key design goals:

* Maximize discovery accuracy and coverage
* Deduplicate and normalize results
* Lightweight and easy to integrate into automation pipelines
* Designed to be used inside larger frameworks (e.g. Phantom Sight)

---

## Features

* Query crt.sh (JSON) and extract subdomains (robust parsing & fallback extraction)
* Resolve candidates (A / CNAME checks) with timeouts to avoid hanging
* Normalize and deduplicate results
* Read targets from STDIN, CLI args, or file (supports bulk workflows)
* Simple, fast concurrency model with sane defaults
* Designed to integrate with other tooling (`httpx`, `nuclei`, `katana`, etc.)

---

## Requirements

* Go 1.20+ (or your preferred build toolchain)
* Network access to external services (crt.sh, DNS, etc.)

---

## Install

```bash
go install -v github.com/Vulnpire/smapper@latest
```

---

## Usage

Basic usage (single domain):

```bash
echo dell.com | smapper
```

Read targets from a file:

```bash
cat input | smapper
```
---

## Output

`smapper` prints one subdomain per line (stdout). Example:

```
www.example.com
api.example.com
assets.example.com
```

This newline-delimited format makes it easy to pipe into `httpx`, `nuclei`, `katana`, or any other tool in your pipeline.

---

## Integration examples

Pipe into `httpx` to check live hosts:

```bash
cat targets.txt | smapper | httpx -silent -title -o live.txt
```

Feed into `nuclei` for quick checks:

```bash
cat example.com | smapper | httpx -silent | nuclei -t ~/nuclei-templates -o findings.txt
```

---

## Best practices & recommendations

* Combine `smapper` output with other passive sources (OSINT, DNS history, certificate transparency) for maximum coverage.
* Use moderate concurrency and timeouts against unfamiliar networks to avoid accidental disruption.
* When automating at scale, aggregate and deduplicate data centrally (Elastic, CSV, or flat-file dedupe).
* Respect target scope and program rules (use test accounts or explicit permission when performing active checks).

---

## Limitations

* `smapper` focuses on discovery + DNS validation. It does not perform deep active scanning, exploitation, or fuzzing.
* Some sources (crt.sh, passive feeds) may rate-limit; the tool implements simple fallbacks but heavy usage should be coordinated.
* Results depend on internet connectivity and third‑party service availability.

---

## Contributing

Contributions are welcome. If you want to add features, please:

1. Fork the repo
2. Create a topic branch
3. Submit a PR with a clear summary, tests (if relevant), and rationale

When contributing, follow the repository's coding style and maintain backward-compatible CLI behaviour where possible.

---

## Security & Responsible Use

This tool is intended for authorized security testing and research. Do **not** use it to scan or probe assets you do not own or do not have permission to test. Always follow legal requirements, program rules (bug bounty scopes), and responsible disclosure practices.

---

## About CyberPars & Phantom Sight

**CyberPars** — new generation cybersecurity company focused on adversary emulation, pentesting, red/blue-team tooling, and offensive research.

We provide:

* Full adversary emulation & red team engagements
* Penetration testing (Web, API, Network, AD)
* Custom tool development (Go, Bash, Python)
* IT security consulting and bespoke automation

**Phantom Sight** is our in‑house framework that orchestrates continuous reconnaissance, exploitation simulation, and alerting. `smapper` is a very lightweight component inside that ecosystem.

---

## Community / Early Access

We’re inviting the first 3 contributors to a **private CyberPars Discord** for collaboration, coordination, new opportunities, and early access to Phantom Sight features.

**Private Discord (first 1 member only):** [https://discord.gg/VxbJGkN627](https://discord.gg/VxbJGkN627)

(If you join, please include your GitHub handle and a short note about what you’d like to help with. This channel is experimental and will be updated as the community grows.)

---

## Contact

* Website: [cyberpars.com](https://cyberpars.com)
* Email: [info@cyberpars.com](mailto:info@cyberpars.com)
* LinkedIn: [https://www.linkedin.com/company/cyberpars/](https://www.linkedin.com/company/cyberpars/)

---

## Changelog / Roadmap (short)

* **v0.1** — initial CRT-based enumeration, normalization & resolution
* **v0.2** — integrate passive sources, optional DNS brute force module, richer output formats (JSON/CSV)
* **future** — tighter Phantom Sight integration, plugins for `httpx`/`nuclei` orchestration, shodan/knock-based enrichments
