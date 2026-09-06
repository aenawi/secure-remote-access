<!--
Thank you. Small PRs land fast; large ones land after a conversation, so if this
is large, an issue first will save you rework.
-->

## What this changes

<!-- One or two sentences. What was wrong, what is now right. -->

Closes #

## Kind

- [ ] Prose — clarity, typo, dead link
- [ ] The advice was wrong, unsafe, or out of date
- [ ] Lab or sandbox — code, checks, a new scenario
- [ ] A divergence between the lab and the sandbox, closed or newly documented
- [ ] Tests
- [ ] Something else

## If this changes advice or a command

<!-- Delete this whole section if it does not apply. -->

**What it was measured against** — a claim here carries a date and a version, or
it is an opinion:

```
OS:
OpenSSH / tailscale / Headscale, as applicable:
Measured on:
```

**What you ran, and what it printed:**

```

```

- [ ] I checked whether any *other* chapter makes the same claim
- [ ] If this step can lock someone out of a machine, the warning sits before the step
- [ ] The mechanism is explained, not just the command

## Checks

- [ ] `make -C lab check` passes
- [ ] `gofmt` is clean (`make check` fails on any output at all)
- [ ] New source files carry an `SPDX-License-Identifier` header

## If this touches the guide's pages

- [ ] It still works from `file://` — no build step, no fetch, no new dependency
- [ ] It still reads with JavaScript off
- [ ] Any new simulation has a `data-poster` frame chosen deliberately
- [ ] New or moved chapters are registered in `assets/nav.js`

## If this touches the lab or sandbox engine

- [ ] Nothing is drawn that was not measured
- [ ] A failed attack does not render as a green tick
- [ ] `danger` still outranks `ok`
- [ ] Time is not faked
- [ ] The engine still returns the rung that decided the outcome, not a bare pass/fail
- [ ] If a score moved, the comparison table in `lab/README.md` moved with it (a
      test asserts these against a fixture, so a mismatch will fail loudly)

## Licence

- [ ] I have the right to submit this, and I am fine with it going out under
      CC BY-SA 4.0 (guide) or GPL-3.0-or-later (code), per the file I touched
