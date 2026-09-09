# Contributing

## Do not argue with me. Beat me in the lab.

Most security disagreements are two people trading confident opinions and
neither of them moving. This repository has a way out of that, and it is the
reason to bother contributing here rather than leaving a comment somewhere.

The guide ships two versions of the same network.
[Chapter 14](chapters/14-sandbox.html) simulates it in your browser; that one is
**the sandbox**. [`lab/`](lab/README.md) builds it for real, in containers: four
machines on four isolated segments, each behind its own NAT router, running real
`tailscaled` on real TUN devices; that one is **the lab**. Run the same test
against both and they should give you the same answer.

Sometimes they do not, and when that happens one of the two is wrong about how
the real world behaves. Every disagreement found so far is written up in
[Where this lab and the sandbox disagree](lab/README.md#where-this-lab-and-the-sandbox-disagree),
with what we measured, when, and which half we changed. Sometimes we corrected
the sandbox. Sometimes we corrected the lab. Once Headscale shipped the feature
the gap was made of and closed it for us.

Finding a new disagreement is the most valuable thing you can contribute. It is
also the most fun, and it is the only kind of contribution where being right
costs me a chapter rewrite and earns you a credit in the file.

So: if you think a chapter is wrong, you do not have to convince me. Build the
case where it fails.

```bash
cd lab
make up          # four machines, ~2 minutes, Docker is the only prerequisite
make audit       # the eleven checks, scored, from the command line
make attack      # add the attacker container — it never starts on its own
```

## Four things worth sending, most valuable first

### 1 · A divergence

The sandbox says one thing, the lab says another. Open an issue with
**Disagreement** on it. Say which configuration (`day-one`, `typical`, `weak`,
`hardened`, or the boot state), what you ran, what each half reported.

Findings get a date and a version, not a verdict. Every entry in that section
names what it was last measured against, because Headscale is pinned
(`headscale/headscale:0.29.3`) and the tailscale client is not. A divergence is
a fact with a date on it rather than a property of the world. Finding 1 is in
that file precisely because it was once written without one.

### 2 · The advice is wrong

Not the lab, the guide. A command that does not do what chapter 08 says it does.
A `sshd_config` key whose first-value-wins behaviour bites in a way the chapter
misses. A macOS release that moved the SACL. A claim that was true in August
2026 and is not true now.

Open an issue with **Disagreement**. Bring your OS and version numbers. "It
doesn't work" is unactionable; "OpenSSH 10.2 on Ubuntu 24.04, here is `sshd -T`"
is a fix.

You do not need a lab repro for this. It helps, and if the claim is one the lab
can hold, turning it into a check is the difference between a fix and a fix that
cannot silently regress.

### 3 · You got lost

This one surprises people, so it is worth saying plainly: a beginner reporting
confusion is a real bug report, and I want it.

The guide is written for someone who can build software and has never had to
defend it. If you are that reader and a paragraph lost you, the paragraph is
broken, not you. Tell me where you stopped and what you thought the sentence
meant. Open an issue with **I got lost**.

There is no such thing as too obvious a question here. The failure mode this
guide is most at risk of is being written by someone who already knows, for
someone who already knows.

### 4 · Prose, commands, code

Typos, dead links, a clearer sentence, a diagram step that skips a beat, a Go
test, a new sandbox scenario. Send the PR.

## Which branch to start from

Branch from `develop`. Never from `main`.

`develop` is the default branch, so a fresh `git clone` already puts you on it
and the pull request box already points at it. If you took a copy before that
changed, or you are working from a fork that has drifted, check:

```bash
git checkout develop
git pull origin develop
git checkout -b your-branch
```

### What each branch is

`main` is the published guide, and nothing else. It is what
[aenawi.github.io/secure-remote-access](https://aenawi.github.io/secure-remote-access/)
serves. A commit reaching it is a release: somebody's phone now shows that
sentence, and somebody may run the command in it tonight against a machine they
cannot walk over to. Nothing lands there because it compiles. It lands there
because it is ready to be followed.

`develop` is where the work happens. Everything merges here first: a fix, a
new chapter, a lab scenario, a typo. It is expected to be good and not expected
to be released. Nothing on `develop` is visible to a reader, which is exactly
what makes it the right place to be wrong in public for a while.

Your branch comes off `develop` and goes back into `develop`. One idea per
branch. Name it for what it does: `fix/ufw-docker-ordering`,
`chapter/15-backups`, `lab/expiry-divergence`.

```text
  your branch  ──►  develop  ──►  main  ──►  the published guide
                       ▲            │
                       └────────────┘
                     a release, back-merged
```

### Releases

Periodically `develop` goes to `main` as one pull request titled for the release.
That is the only routine way anything reaches `main`. It is a deliberate act, not
a consequence of merging. The point of the split is that shipping is a decision
somebody makes on purpose.

Squash every branch into `develop`. Never squash `develop` into `main`.

That is not a style preference and it is the one mistake in this model that gets
worse the longer it goes unnoticed. Squashing writes a *new* commit with no link
to the ones it replaced. Inside `develop` that is exactly what you want: one
readable commit per idea. But squashing a release makes `main` a branch that
merely resembles `develop` rather than one that contains it, so the next release
re-offers every change again, conflicting against the copy already sitting there,
and every release after that is worse.

```bash
gh pr merge <n> --merge      # releases, and hotfixes back into develop
gh pr merge <n> --squash     # everything else
```

A release keeps the individual commits. That is the second reason for the merge:
`main`'s history is then the list of what shipped and when, which is the question
you will actually ask it later.

### Hotfixes: the exception, and why it exists

If published advice is dangerous, it does not wait for a release.

This guide tells people to change firewall rules, disable password login and
remove the only route into a machine they may be a long way from. If a chapter
on `main` is wrong in a way that locks somebody out or leaves them exposed, the
release train is not a process; it is a delay with a cost attached.

So there is one lane straight to `main`:

```bash
git checkout main
git pull origin main
git checkout -b hotfix/what-it-fixes
# fix it, open a PR into main
```

Once it merges, back-merge `main` into `develop` immediately, or the next
release will quietly revert the fix:

```bash
git checkout develop
git pull origin develop
git merge origin/main
git push origin develop
```

Hotfixes are for harm, not for hurry. A typo is not a hotfix. "It has been wrong
for a week and I want it fixed" is not a hotfix. The question is only whether a
reader following the current published text gets hurt before the next release.
If you are unsure, it is not one. Open it against `develop` and say in the PR
that you think it might warrant a hotfix, and it can be retargeted.

## Running the checks

```bash
cd lab
make check       # the one target that runs with the lab down — Go and JavaScript
make hooks       # install the pre-push hook that runs make check for you
```

The same `make check` runs on GitHub for every pull request into `develop` and
`main` (see [`.github/workflows/check.yml`](.github/workflows/check.yml)), and
both branches require it to pass before anything merges. The hook is the fast
copy on your laptop; CI is the one that counts, because a fork does not have
your hook and `--no-verify` skips it.

`make check` wants Go rather than Docker and finishes in about a second: `go vet`,
`go test`, `gofmt -l` and a parse-check over `assets/*.js` and the lab UI. It also
asserts the five scores in the comparison table against a checked-in fixture, so a
number in the README and the number `audit.go` computes cannot drift apart
without a failing test naming both.

Two shell checks run before the Go does, and both guard a claim rather than a
behaviour. `checks/licensed.sh` fails if a source file under `assets/` or `lab/`
has no SPDX header. `checks/anchors.sh` fails if a link between two documents
here points at a heading that is not there — which is what keeps a pointer from
quietly becoming worse than the duplicate it replaced.

`gofmt` fails on any output at all. A file listed is a file that is not
formatted.

Run `make hooks` once and you will stop thinking about this.

## Things the repository holds, that a PR should not quietly break

These are invariants rather than preferences. If your change needs one of them
gone, that is a conversation worth having in an issue first, but it is a
conversation, not a footnote in a diff.

The guide works from `file://`. No build step, no server, no dependencies,
double-click `index.html` and it works offline. This is why `nav.js` is a plain
global instead of a fetch: `fetch()` is blocked on the `file:` scheme.

Everything degrades without JavaScript. `anim.js` and `sandbox.js` are opt-in
per page and add a class when they take over; `style.css` hides scenario layers
except those tagged `data-poster` until then. Any new simulation needs a
`data-poster` frame chosen deliberately, because it is the one coherent picture
a reader sees with scripting off.

A simulation is declared in markup. `data-sim`, `data-at`, `data-scn`,
`data-flow`. No per-diagram JavaScript.

`nav.js` is the single source of truth for navigation. Add an entry there and
the sidebar, filter, chapter cards and prev/next links all pick it up.

The engine returns the rung, never a bare pass/fail. Both halves walk the
chapter 12 ladder in order and report which rung decided the outcome. That is the
thing worth preserving above all if you extend either.

The four board rules. Nothing drawn that was not measured. A failed attack is
not a green tick. `danger` outranks `ok`. Time is not faked. Four Go test files
guard these; they are the kind of invariant that erodes without anyone deciding
to erode it.

Mechanism before command. A reader who runs a line they do not understand
cannot debug it later, and the whole guide is aimed at the moment when they have
to.

SPDX headers on every source file. `lab/checks/licensed.sh` fails without
one, and `make check` runs it.

Each fact has one home, and the other documents link to it. `README.md`
orients — what this is, who it is for, how to open it, what is in it. The
invariants above live here. The disclaimer lives in `index.html`, where a
reader is standing when it matters, and every other mention points there. The
temptation is always to restate the thing for the convenience of a reader who
has not clicked; resist it, because the copy is the one that goes stale, and a
stale disclaimer is the worst of them to own two of.
`lab/checks/anchors.sh` guards the links this asks you to write.

## Style

British spelling, Oxford commas optional, prose over bullets where the idea has
a shape. Sentences may be long if they earn it.

Say what was measured and when. "Tailscale does X" is weaker than "tailscale
1.102.3 did X on 2026-08-14, here is the output". The second one stays true
when it stops being true, because it says which build it was about.

Where a step can lock someone out of a machine they cannot walk over to, say so
*before* the step, and say what the second way in should be.

## Licensing your contribution

The repository is two licences, and your contribution takes whichever covers the
file you touched:

- Guide (`index.html`, `chapters/`, `README.md`): [CC BY-SA 4.0](LICENSE-docs)
- Code (`assets/`, `lab/`): [GPL-3.0-or-later](LICENSE)

Opening a PR means you are fine with that, and that you have the right to send
what you sent. No CLA, no copyright assignment, nothing to sign. You keep your
copyright; the licence is what travels.

## What I will say no to

Not to be discouraging, but to save you the afternoon.

- A build step, a bundler, a framework, or a runtime dependency for the guide.
- A JavaScript library added to a chapter page.
- Vendor recommendations, affiliate links, or a product placed as advice.
- A scenario in the sandbox that draws something the engine did not compute.
- Confident security claims with no version, no date and no way to check them.

## Reporting a vulnerability

Not here. See [SECURITY.md](SECURITY.md). That covers both a flaw in the lab's
code and, more likely, dangerous advice in a chapter.
