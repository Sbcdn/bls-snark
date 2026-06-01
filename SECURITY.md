# Security policy

`bls-snark` produces cryptographic artifacts for on-chain verification. Bugs here cause silently accepted bad proofs or silently rejected good ones.

## Reporting a vulnerability

Email **sbcdn@pm.me** with a description, a reproducer if possible, and an impact assessment. Do not open public GitHub issues for vulnerabilities until a fix is available.

Expected initial acknowledgement: within 5 business days. Coordinated disclosure preferred.

## Scope

In scope:

- Soundness gaps that let `bls-snark` produce an outer proof attesting to something it shouldn't.
- Completeness gaps that reject a wrap that should succeed.
- Trust-boundary issues in input parsing (snarkjs JSON, risc0 receipt, `risc0_params.json` sidecar).
- Defaults that silently degrade security.

Out of scope:

- The on-chain Aiken verifier (separate repo).
- Bugs in upstream `gnark`, `gnark-crypto`, `risc0-zkvm`, `risc0-groth16`. Report upstream; pin will move once a fix lands.
- Operator-attacks-self threats (running the CLI with deliberately malicious flags against own files).

## Supported versions

Pre-1.0. Only the tip of `main` is supported.

## Audit history

- **2026-05-29** — internal 4-reviewer audit (Rust engineering, security engineering, ZK protocol, pedantic review). No soundness-critical or security-critical findings; hardening items tracked and addressed.
- **2026-05-31** — hardening batch: bounded untrusted-input parsing (size caps, alloc guards, overflow) + Go fuzz targets; refused the single-party setup without `--insecure-dev-setup`; `--out-dir` path-traversal guard.
- **2026-05-31** — production-readiness audit (5-agent: ZK protocol, Go engineering, Groth16, interface-security, whitehat). No forgery: a tampered proof could not be made to verify against wrong data. Hardening: mandatory compressed/uncompressed commitment cross-check + tamper test; reject proof points at infinity; reject non-canonical public limbs (≥ r); `export` asserts `nC==1`; dumper test diffing `build_vk_json()` against `risc0_groth16::verifying_key()`. Still **no external audit** — required before production.

Automated checks (CI `lint-audit` job): `golangci-lint` (incl. `gosec`) + `govulncheck` (fail on findings) and `cargo audit` for the Rust dumper deps (report-only — risc0-pinned). Parser/byte-reader fuzz targets in `internal/{parser,cardanoref}`.

No external audit yet. Required before production deployment.

## Known security-relevant limitations

- **Trusted setup** single-party path is **refused unless `--insecure-dev-setup`** (or `BLS_SNARK_INSECURE_DEV_SETUP=1`) is given; it's dev-only and toxic-waste-equivalent. When it runs, the result JSON stamps `"mode": "insecure-dev-setup"` and a multi-line `INSECURE` banner is logged. Production setups MUST use `--pk-input` / `--vk-input` passthrough against an MPC ceremony output.
- **The on-chain verifier** is the consumer's deliverable. The Go reference verifier in `internal/cardanoref/` is the soundness oracle.
- **Receipt fingerprint check** in `tools/risc0-dump` can be bypassed with `--accept-fingerprint <hex>` or `--insecure-skip-fingerprint-check`. Both emit a single-line `WARN:` to stderr regardless of receipt content; absence of that warning is the affirmative signal that the canonical default was used.
- **Inner-VK fingerprint check** in `bls-snark setup` can be bypassed with `--insecure-no-vk-check` or overridden with `--inner-vk-fingerprint`. The setup result JSON stamps the resolved fingerprint (`inner_vk_fingerprint`) for post-hoc audit.
