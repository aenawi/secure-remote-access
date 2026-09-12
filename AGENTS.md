# Working on this repository as an agent

This file is for AI coding agents — Claude Code, Copilot, Cursor, Codex, and
whatever comes next. It does not replace [CONTRIBUTING.md](CONTRIBUTING.md),
which binds you exactly as it binds a person. Read that first. What follows is
only the part that is different when the contributor is a model: the rules a
human keeps by accident, and an agent breaks by being efficient.

Nothing here is a preference. Every rule below is here because it was broken,
and the break cost something.

## Use the templates. They are not decoration

`gh issue create --body "..."` and `gh pr create --body "..."` bypass
[`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/) and
[`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) silently.
No warning, no error, a green tick and a URL. This is the single easiest rule in
the repository for an agent to break, because the tool that breaks it is the
convenient one.

So: open the template, fill in its sections, keep its title prefix.

- A bug gets `[bug] ` and the **Environment** block, which is a required field.
  Host OS, Docker, browser, Go. A claim with no version and no date is an
  opinion — that is the house [style](CONTRIBUTING.md#style), and the form is
  where it is enforced.
- A disagreement between the lab and the sandbox gets the **Disagreement**
  template, and a date, and the versions both halves were running.
- A pull request gets the checklists. They are short and every box is a real
  question. The engine boxes in particular — *nothing is drawn that was not
  measured*, *a failed attack does not render as a green tick* — are the
  invariants this project exists to protect, and ticking them means you checked,
  not that you intend to.

If a template genuinely does not fit what you are reporting, say so in the issue
rather than skipping the form.

## Say what you measured, not what you expect

You have a shell. Use it, and then quote it.

Do not write a number, a version, a timing or an outcome you did not observe.
Do not describe what a command "would" print. If a thing is untested, the
honest sentence is that it is untested, and that sentence is welcome.

Where a claim is about behaviour, it carries what it was measured against and
when — `tailscale 1.102.4 on 2026-09-12, here is the output` — because that
stays true after it stops being true. Headscale is pinned in the compose file
and the tailscale client is not, so "the lab does X" has a shelf life and
"the lab did X on this date against these versions" does not.

## The lab may be running, and it may not be yours

`lab/` starts real containers. Someone may be in the middle of using them.

Treat `make reset`, `make down`, `docker rm`, `docker stop` and anything with
`--force` as destructive to a person, not to a fixture. Do not run them on a lab
you did not start yourself, unless you were asked to. If measuring something
requires stopping a container — sometimes it does, and the measurement is worth
having — put it back afterwards, verify it came back, and say in your report
that you did both.

Prefer the narrow command. `docker compose up -d --build --no-deps <service>`
rebuilds one container; `docker compose up -d --build` may recreate every
container and discard configuration somebody applied by hand a minute ago.

The attacker is subject to [the lab's own safety
rules](lab/README.md#safety-before-anything-else). `evil-box` is behind a
profile, it never starts on its own, and that is a property to preserve rather
than a friction to smooth away.

## Editing the UI changes nothing until you rebuild

`lab/control/ui/` is compiled into the control server with `//go:embed`. Editing
`style.css` or `app.js` and reloading the page shows you the old file, because
the server is still serving the bytes it was built with. Rebuild:

```sh
docker compose up -d --build --no-deps control
```

Then confirm the server is actually serving your change — `curl` the asset and
grep it — before concluding anything about whether the change worked. The
browser caches these aggressively too, so a hard reload is part of the loop.

This has already sent one session off to debug a fix that was correct the whole
time.

## Verify in the lab, not only in the tests

`make check` runs without Docker and finishes in about a second. It is necessary
and it is not sufficient: it proves the code compiles, is formatted, is licensed
and that the parsers still parse. It cannot tell you whether the thing you built
behaves as claimed against real containers.

If you changed behaviour, drive it. Hit the API, press the switch, run the
attack, and paste what came back.

## Do not make the two halves agree by hand

The sandbox on chapter 14 and the lab in `lab/` are two implementations of one
network, and where they disagree the disagreement is the most valuable output
this repository produces. They are written up in [where this lab and the sandbox
disagree](lab/README.md#where-this-lab-and-the-sandbox-disagree).

Find the cause before you honour a divergence *or* fix it. A real
model-versus-reality gap gets documented and kept. A gap that exists because the
lab's own configuration was wrong gets fixed. Deciding which one you have is the
work; assuming is how a genuine finding gets quietly deleted, and how a
configuration bug gets enshrined as a fact about the world.

## Scope: one idea per branch

Branch from `develop`, never `main` — the model and its reasoning are in
[which branch to start from](CONTRIBUTING.md#which-branch-to-start-from).

An agent that has found three problems is tempted to fix three problems. Do not.
Each goes on its own branch off `develop` with its own pull request, because a
branch is the unit that gets reviewed, reverted and understood later. If you
find something adjacent while fixing something else, finish the thing you are
on, then say what else you found — as an issue, or in the pull request body
under a heading that says it is not in this change.

## Do not add dependencies, build steps or frameworks

This is the top of [what I will say
no to](CONTRIBUTING.md#what-i-will-say-no-to), and it is the one an agent is
most likely to reach for, because a library is usually the shortest path.

The guide works from `file://` with no build step, no bundler and no runtime
dependency, and it degrades with JavaScript off. The lab needs Docker and
nothing else — no Go on the host, no npm, no account. Those are the properties
that make both usable by the reader this guide is written for. A change that
costs one of them is not a smaller change than doing it the long way.

The full list of what a pull request must not quietly break is in
[things the repository holds](CONTRIBUTING.md#things-the-repository-holds-that-a-pr-should-not-quietly-break).
Read it before touching the engine, the navigation or the stylesheet.

## Before you push

```sh
make -C lab check
```

It runs the licence check, the anchor check, `go vet`, `go test`, `gofmt` and a
parse of the UI JavaScript. `gofmt` fails on any output at all. New source files
under `assets/` or `lab/` need an `SPDX-License-Identifier` header or the
licence check fails — and it exists to catch a file *born* without one, which is
exactly what a generated file is.

`make -C lab hooks` installs a pre-push hook that runs it for you. CI runs it
again on every pull request, and that is the one that counts.

## Security work

Do not open a public issue for a vulnerability, in the code or in the advice.
[SECURITY.md](SECURITY.md) says where it goes. This guide tells people to change
firewall rules and remove their own access to machines they cannot walk over to;
advice that is wrong in that direction hurts somebody, and the disclosure path
exists for that reason.
