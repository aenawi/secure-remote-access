# Security policy

This repository is a guide, a simulation and a lab. That means there are two
quite different kinds of security report, and the more dangerous one is not the
one people expect.

## Dangerous advice is the real vulnerability here

Nothing in this repository runs on your infrastructure. The guide's readers do.

So the finding that matters most is not a bug in `control/` — it is a chapter
that tells someone to do something unsafe, or safe-but-in-the-wrong-order, on a
machine they cannot walk over to. A `ufw` rule that opens more than it reads
like it opens. A hardening step that silently leaves password auth reachable. An
ordering that closes the only route in before the new one is proven. A key
custody instruction that puts the private half somewhere it should never be.

**Report those privately, the same as a code vulnerability.** A chapter that
locks people out, or quietly leaves them exposed, deserves a fix before it
deserves a public thread.

## How to report

Use GitHub's private vulnerability reporting:

**[Report a vulnerability](https://github.com/aenawi/secure-remote-access/security/advisories/new)**
— Security tab → Report a vulnerability.

That opens a private advisory only you and the maintainer can read. Please do
not open a public issue for anything in the two categories above.

Include, as far as you have it:

- Which chapter, or which file and line.
- What the advice or code does, versus what a reader would reasonably expect.
- The concrete harm — exposed, locked out, key disclosed, and to whom.
- Versions: OS, OpenSSH, tailscale client, Headscale, whatever applies.
- A lab repro if the claim is one [`lab/`](lab/README.md) can hold. Not required.

## What to expect

This is a personal project, not a vendor, so no SLA — but the intent is:

| | |
|---|---|
| Acknowledgement | within 7 days |
| First assessment | within 14 days |
| Fix or a public explanation of why not | as fast as the finding is bad |

That last row has a lane behind it rather than a good intention. `main` is the
published guide and normally only changes when a release is cut, but advice that
locks a reader out or leaves them exposed goes straight there as a **hotfix** and
is back-merged afterwards — see
[CONTRIBUTING.md](CONTRIBUTING.md#hotfixes--the-exception-and-why-it-exists).
A release train is a delay with a cost attached, and this is the category where
that cost lands on somebody else's machine.

Credit in the fix commit and in the chapter, unless you would rather not be
named. There is no bounty; there is no budget.

## In scope

- **The guide** — `index.html`, `chapters/` — advice that exposes, locks out, or
  loses keys when followed as written.
- **The lab** — `lab/` — anything that escapes its own containers, exposes a
  service on the host that the README says is internal, or reports a machine as
  secure when it is not. A green check that should be red is a real finding here,
  because the whole point of the audit is that people trust its answer.
- **The sandbox** — `assets/sandbox.js` — a scenario that models an attack as
  blocked when the real stack would let it through. It is a teaching model, so
  the bar is "would this teach someone something false and load-bearing", not
  "is it a perfect simulation".

## Out of scope

- The lab being insecure on purpose. `weak` and `day-one` are meant to fail
  checks, and `evil-box` is an attacker container that ships in the repo. That
  is the exhibit, not the bug. If you can make it do something the README does
  not describe, that *is* in scope.
- Anything requiring you to already have root on the host running the lab.
- Missing hardening on a static HTML page with no server, no backend and no
  user data.
- Third-party vulnerabilities in Headscale, tailscale, Docker or three.js —
  report those upstream. Do tell me if a version this repo pins is affected, so
  the pin can move.
- Automated scanner output with no demonstrated impact.

## A note on the disclaimer

The [README's disclaimer](README.md#disclaimer) says there is no warranty and
that the outcome of running these commands is yours. That stays true, and it is
not in tension with this file. No warranty is a statement about liability. This
file is a statement about intent: if a chapter here is dangerous, tell me, and
it gets fixed.
