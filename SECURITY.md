# Security Policy

## Supported versions

The `main` branch is the only supported version. Fixes land there and are
included in the next tagged release.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Use GitHub's [private vulnerability reporting](https://github.com/mojtaba-py-code/big-data-log-analytics-platform/security/advisories/new),
or email **mojtaba.python@gmail.com** with `SECURITY` in the subject line.

Useful things to include, if you have them: the affected component, a minimal
reproduction, and what an attacker gains. A rough report is better than none —
send what you have.

You can expect an acknowledgement within 72 hours and a fix or a clear decision
within 30 days. I will credit you in the release notes unless you'd rather I
didn't.

## Scope

In scope: anything in `app/`, the container image, the CI workflows, and the
default configuration in `configs/`.

Out of scope: findings that require an already-compromised host, denial of
service through unbounded input the operator chose to accept, and issues in
third-party dependencies that already have a public advisory — those are caught
by the `pip-audit` job and handled as ordinary dependency bumps.

## How this project defends itself

The threat model, the control that answers each threat, and the test that proves
the control works are documented in [`docs/SECURITY.md`](docs/SECURITY.md).
Every control there has a corresponding test in `tests/security/`, and the suite
runs on every push.
