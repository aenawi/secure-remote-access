# Secure Remote Access: a guide

A self-contained HTML guide to reaching your own laptops, servers and phones
from anywhere: privately, and without losing your session when the connection
drops.

It is built in two separable layers. The **network layer** (chapters 01, 02 and
the per-machine hardening chapters) gives you private reachability and is useful
whatever you point at it. The **session layer** (chapters 03 and 04, Mosh and
tmux) is what turns that into somewhere you can work for hours from a phone on a
moving train. Build the first alone if that is all you need.

## Who this is for

Someone who can build things but has never had to defend them.

That describes far more people than it used to. An AI coding assistant will hand
you a working service, a database and a deployment in an afternoon, and none of
it arrives with a threat model attached. The code runs, and the machine it runs
on is now reachable, holds your keys, your customers' data, and whatever the
assistant was given permission to read. The first half of shipping got easy. The
second half did not.

So the guide assumes you know how to make software and not how to lock a door.
It explains the mechanism before the command (what a key type actually proves,
what a firewall rule does to a packet), because a command you do not understand
is a command you cannot debug at two in the morning from a phone. Where a step
can lock you out of your own machine, it says so before the step, not after.

If you already run infrastructure for a living you are not the reader. You may
well be the reviewer, though, and [CONTRIBUTING.md](CONTRIBUTING.md) is written
for you: the lab turns "I think that is wrong" into a test that either fails or
does not.

## Open it

```bash
open index.html
```

No build step, no server, no dependencies. It works from `file://` and offline.
If you would rather serve it:

```bash
python3 -m http.server -d . 8080   # then visit http://localhost:8080
```

## Contents

| # | Chapter | Covers |
|---|---------|--------|
| — | `index.html` | The whole picture: four machines, three planes, how the layers stack (the phone role covers both iOS and Android) |
| 01 | Tailscale & WireGuard | Cryptokey routing, NAT traversal, DERP, ACLs, tailnet lock |
| 02 | SSH, keys & hardening | The auth handshake, key types, `sshd_config`, macOS PAM/SACL |
| 03 | Mosh & Blink Shell | Why SSH dies on mobile, the state-sync protocol, Secure Enclave keys |
| 04 | tmux & Herdr | Session persistence, agent multiplexing, the prefix collision |
| 05 | Securing the MacBook Pro | FileVault, port audit, sshd as a launchd daemon, tailnet-only bind, reaching a local service from the phone |
| 06 | The iPhone client | Device hardening, Blink setup, Mosh, saved hosts |
| 07 | The Android client | Termux, key custody without an enclave, Doze and per-vendor app killing |
| 08 | Hardening a Linux VPS | First ten minutes, UFW, closing public SSH, Docker's UFW bypass |
| 09 | The Ubuntu laptop | LUKS, Secure Boot, MAC randomisation, hostile networks |
| 10 | Threat model & key custody | Who you are defending against, blast radius, incident response |
| 11 | Runbooks & checklists | Build order, onboarding, rotation, the full deployment checklist |
| 12 | Troubleshooting | A five-rung diagnostic ladder and a symptom reference |
| 13 | The lab | Three throwaway VMs, a deliberately hostile network, and a pass/fail test per chapter |
| 14 | The sandbox | The same topology as an operable model: flip switches, add a hostile machine, read which rung stopped it |
| — | [`lab/`](lab/README.md) | The same topology as real containers: `docker compose up`, then drive it from a browser |

## Features

Every chapter carries stepped simulations rather than static pictures. Pick a
scenario, then step through it with the controls or the arrow keys. The drawing,
the narration and a mock terminal all advance together, so you can watch a NAT
punch through, an SSH replay get rejected, or a launchd job fall into a restart
loop. With JavaScript off each one collapses to a readable static poster frame.

Chapter 14 goes further and drops the timeline entirely. It holds state, a rules
engine and a render, so you change something and it works out the consequence.
Close a port, kill a link, leak a node key, put a hostile machine on the wire,
and every probe reports the rung of the diagnostic ladder that decided it, with
round-trip times, byte counts and retransmits. The keypairs and the AES-GCM seal
are genuine WebCrypto, so when the attacker fails to decrypt a captured frame it
is the cipher refusing, in your browser. Everything you do there also emits the
real `nft` / `tc` / `ufw` / `tailscale` command, so the page doubles as a script
generator for the chapter 13 VMs.

Smaller things: checklist ticks are saved in `localStorage`, per chapter, and
the full deployment checklist in chapter 11 has a progress bar and a reset
button. Dark and light themes follow your system by default, with a toggle that
overrides and remembers. Command blocks copy to the clipboard on a click. The
SVG is inline throughout, themed with the page rather than shipped as images. It
is responsive enough to be genuinely readable on the phone the guide is about,
and printable, with the navigation chrome hidden in print stylesheets.

## Structure

```text
secure-remote-access/
├── index.html
├── assets/
│   ├── style.css      design tokens, layout, components, SVG theming hooks
│   ├── nav.js         the chapter index — edit here to add or reorder chapters
│   ├── app.js         theme, sidebar, TOC, chapter filter, copy buttons, checklists
│   ├── anim.js        the stepped diagram simulations
│   ├── sandbox.js     the sandbox: state, the five-rung engine, the attacks
│   └── favicon.svg
├── chapters/
│   └── 01-…-14-….html
└── lab/               the same topology as containers — see lab/README.md
    ├── docker-compose.yml
    ├── Makefile       up / attack / audit / reset
    ├── config/        the coordination server's configuration
    ├── images/        one lab machine, one NAT router, one attacker
    └── control/       a Go control server with its UI compiled in
```

`lab/` is the one part of this repository that is not a static page. It is
opt-in, self-contained and needs nothing but Docker; the guide reads exactly the
same without it.

Those files hold to a handful of rules that are easier to break than to notice
broken — why `nav.js` is a plain global rather than a fetch, how a simulation is
declared in markup, what the sandbox engine has to return, which frame a reader
sees with scripting off. They are written down once, in
[Things the repository holds, that a PR should not quietly break](CONTRIBUTING.md#things-the-repository-holds-that-a-pr-should-not-quietly-break),
next to [the checks](CONTRIBUTING.md#running-the-checks) that guard the ones a
machine can guard.

## Contributing

The short version: **do not argue with me, beat me in the lab.**

Chapter 14 simulates this network in your browser and [`lab/`](lab/README.md)
builds it for real in containers, which is what makes a claim here falsifiable
rather than merely confident: run the same test against both halves, and a
disagreement between them is a fact about the world instead of an opinion about
it. Finding one is the most useful thing you can contribute.
[CONTRIBUTING.md](CONTRIBUTING.md) says how to go looking, and
[Where this lab and the sandbox disagree](lab/README.md#where-this-lab-and-the-sandbox-disagree)
records every one found so far, with what was measured and which half moved.

You do not need a lab repro to be useful, though. A dead link, a command that
has moved on, a paragraph that lost you — especially a paragraph that lost you —
are each worth an issue.

Branch from `develop`, never from `main`. `develop` is the default branch, so a
fresh clone already puts you there. `main` is the published guide and nothing
else — a commit reaching it is a release, and somebody may run that command
tonight against a machine they cannot walk over to.

- [CONTRIBUTING.md](CONTRIBUTING.md): what is worth sending, which branch to
  start from, how to run the checks, and the invariants a change should not
  quietly break
- [SECURITY.md](SECURITY.md): advice that would expose or lock out a reader is
  a vulnerability, and goes privately first
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): attack the claim, never the person

## Disclaimer

The commands in this guide change firewall rules, disable password login,
rewrite `sshd_config`, and deliberately remove the only route into a machine you
may be a long way from. In the wrong order, on a box you cannot walk over to,
several of them will lock you out. The guide says so at every point where that
is a real risk; those warnings are not decoration.

There is **no warranty of any kind**. The decision to run any of this is yours,
and so is the outcome. Nobody who wrote, reviewed or contributed to this is
responsible for what happens on your machines.

The guide states that in full, at the point where a reader is standing in front
of it: [Disclaimer](https://aenawi.github.io/secure-remote-access/#disclaimer),
which is the Disclaimer section of `index.html` if you are reading offline. It is worth the two minutes before you run anything against something
you care about — the short of it is that your environment is not this one, that
chapters 13 and 14 and `lab/` exist so you can practise somewhere disposable,
and that you should have a second way into the machine, proven working, before
you change anything.

## A note on accuracy

Commands were written against macOS 26, Ubuntu 24.04 LTS, OpenSSH 10.x and
Tailscale as of August 2026. Three things move fastest and are worth checking
against their own docs rather than trusting any guide:

- Herdr is young; keybindings and config keys are still settling. Use
  `herdr --default-config` and `prefix + ?` on your installed version.
- Tailscale SSH server support is Linux plus the open-source macOS CLI build
  only, *not* the standard macOS app.
- Android vendor settings (chapter 07) move constantly and differ per handset
  and per OS version. The setting *names* are stable enough to search for; the menu
  paths are not. [dontkillmyapp.com](https://dontkillmyapp.com/) tracks them per
  vendor and is more current than this guide can be.

## License

Two licenses, because this repository is two things.

The guide (`index.html`, everything in `chapters/`, and this README) is
[CC BY-SA 4.0](LICENSE-docs). Read it, quote it, translate it, teach from it,
sell a course built on it. The one condition: if you publish a changed or
extended version, publish it under the same license so the next person gets what
you got.

The code (everything in `assets/` and `lab/`) is [GPL-3.0-or-later](LICENSE).
Same bargain, expressed in the language the FSF wrote for software: run it, study
it, change it, ship it. If you distribute your changed version, ship the source
too.

That is the whole point of the split. Neither license asks you for money or
permission. Both ask that improvements stay reachable by the people who would
learn from them, which is the only reason this exists. Both also come with no
warranty, which is the disclaimer above stated in the language a lawyer would
use.

`SPDX-License-Identifier` headers on each source file say which applies, so the
answer travels with the file rather than living only here. `lab/checks/licensed.sh`
fails if a source file under `assets/` or `lab/` is missing one; `make check` runs
it and the pre-push hook runs `make check`, which is there to catch the file that
gets *written* without a header rather than the one that loses it.

### Third-party

`lab/control/ui/hud/three.module.js` is [three.js](https://threejs.org) r166,
Copyright 2010–2024 Three.js Authors, MIT. The same bundle is inlined inside
`lab/design/five-gates.html` for the reason that file explains. Its MIT notice is
preserved at the head of both copies, and it is not covered by the GPL grant
above; it stays under its own license, which the GPL is happy to accommodate.

Go dependencies under `lab/control/` are MIT, Apache-2.0 and BSD; see
`lab/control/go.sum` and each module's own license.
