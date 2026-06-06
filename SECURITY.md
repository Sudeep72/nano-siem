# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ Active |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in NanoSIEM, please report it
privately via GitHub's Security Advisories:

1. Go to the [Security tab](https://github.com/Sudeep72/nano-siem/security)
2. Click **"Report a vulnerability"**
3. Fill in the details

You can also email: **sudeep7217@gmail.com** with the subject line
`[NanoSIEM Security] <brief description>`.

## What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected component (`ingestion/`, `sigma/`, `ml/`, etc.)
- Potential impact
- Suggested fix (optional)

## Response Timeline

- Acknowledgement within **48 hours**
- Initial assessment within **7 days**
- Fix or mitigation within **30 days** for confirmed vulnerabilities

## Scope

NanoSIEM is a detection engine intended to run in trusted environments.
The following are in scope:

- Remote code execution via malformed log input
- Sigma rule injection that bypasses detection logic
- Path traversal in rule file loading
- Authentication bypass (when auth is added in future versions)

The following are out of scope:

- Vulnerabilities requiring physical access
- Social engineering
- Denial of service from a high-volume log source (by design — the queue applies backpressure)

## Acknowledgements

Responsible disclosure contributors will be thanked in the CHANGELOG
unless they prefer to remain anonymous.
