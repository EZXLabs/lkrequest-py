# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** — do not open a public
issue for security problems.

- Preferred: use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  ("Report a vulnerability" under the repository's **Security** tab).
- Alternatively, contact the maintainers at the security address listed on the
  project's repository page.

Please include enough detail to reproduce the issue (affected version, a minimal
example, and the observed vs. expected behavior). We aim to acknowledge reports
within a few business days.

## Scope

This project is an HTTP client that performs TLS, proxying, and fingerprint
emulation. Security-relevant areas include certificate verification
(`verify` / custom CA handling), proxy credential handling, and the unsafe
buffer-protocol surface on `Response`. Reports in these areas are especially
welcome.

## Supported versions

Security fixes are applied to the latest released version. Older versions are
addressed on a best-effort basis.
