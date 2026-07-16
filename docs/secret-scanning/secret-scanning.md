# Secret scanning

This repo uses [betterleaks](https://github.com/betterleaks/betterleaks) (a gitleaks
fork) to stop secrets — API keys, tokens, passwords, private keys — from ever being
committed. Detection runs locally as a **pre-commit hook**, driven by the single
[`.betterleaks.toml`](../../.betterleaks.toml) config.

| Layer | What it does | Can it be bypassed? |
| --- | --- | --- |
| **pre-commit hook** | Scans your staged diff on every `git commit`; blocks the commit on a finding. | `--no-verify` (locally). |

> GitHub's own **secret scanning + push protection** is also enabled on this repo at
> the platform level, so a pushed secret is caught server-side even if the local hook
> is skipped.

## Install (one-time, per machine)

```sh
brew install betterleaks
```

> The pre-commit hook degrades gracefully: if `betterleaks` isn't installed it prints a
> warning and skips. Install it to catch secrets before you push.

## Setup

The hook is wired through the [pre-commit framework](https://pre-commit.com/). Activate
it once per clone:

```sh
brew install pre-commit   # or: pipx install pre-commit
pre-commit install        # installs the git hook into .git/hooks
```

## How the pre-commit hook works

On `git commit`, the `betterleaks` hook in
[`.pre-commit-config.yaml`](../../.pre-commit-config.yaml) runs:

```sh
betterleaks git --staged --redact --no-banner -c .betterleaks.toml
```

It scans only the **staged** changes (fast). If a secret is detected the commit is
aborted with a message pointing at the offending finding.

## A secret was flagged — what now?

1. **It's a real secret** → remove it and rotate it if it was ever pushed. GitHub
   workflows should reference GitHub secrets; apps should reference a secret manager.
2. **It's a confirmed false positive** → suppress at the *narrowest* scope, in this order:
   1. **Inline allow** — add `betterleaks:allow` as a comment on the offending line.
      Preferred: it's self-documenting and travels with the line.

      ```py
      demo_token = 'AIza...'  # betterleaks:allow — fake fixture, not a real key
      ```
   2. **Fingerprint** — copy the `Fingerprint:` value from the finding into
      [`.betterleaksignore`](../../.betterleaksignore) with a comment explaining why.

   Keep `.betterleaksignore` as small as possible. Don't widen the prefilter in
   `.betterleaks.toml` unless an entire class of paths is genuinely unscannable.

## Emergency bypass

```sh
git commit --no-verify
```
