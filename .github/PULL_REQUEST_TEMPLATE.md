## What this changes

<!-- One or two sentences. Link the issue it closes, if there is one. -->

## Why

<!-- The problem this solves. Skip if the "what" already makes it obvious. -->

## How it was verified

<!--
Which tests you added or ran, and anything you checked by hand. If the change
touches ingestion or storage, say what dataset you ran it against.
-->

## Checklist

- [ ] `ruff check app tests` and `ruff format --check app tests` pass
- [ ] `mypy app` passes under `--strict`
- [ ] `pytest` passes and coverage stays above the 80 % floor
- [ ] New behaviour has a test; a bug fix has a test that fails without the fix
- [ ] Docs updated if the change is user-visible (README, `docs/`, `--help` text)
- [ ] No secrets, tokens or real hostnames in the diff
