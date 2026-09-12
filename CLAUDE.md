# Claude Code, in this repository

**The rules are in [AGENTS.md](AGENTS.md). Read it before you change anything,
open an issue, or open a pull request.** They apply to every AI coding agent and
they apply to you. This file does not restate them — a second copy is the copy
that goes stale, which is the reason
[each fact here has one home](CONTRIBUTING.md#things-the-repository-holds-that-a-pr-should-not-quietly-break).

Behind AGENTS.md sits [CONTRIBUTING.md](CONTRIBUTING.md), which binds you
exactly as it binds a person.

What is below is only what is specific to running as Claude Code here.

## `gh` will let you skip the forms

You have the GitHub CLI, so filing an issue or a pull request is one command,
and that command takes a `--body`. Passing one bypasses the repository's issue
and pull request templates with no warning and no error — you get a green tick
and a URL, and the form is simply not there.

This has happened. Two pull requests and two issues went in free-form before
anyone noticed, and the required Environment block was missing from both issues.

So before `gh issue create` or `gh pr create`, open the relevant file under
[`.github/`](.github/) and answer its sections. The rule and the reasoning are
in [AGENTS.md](AGENTS.md#use-the-templates-they-are-not-decoration).

## Finish the turn against the real thing

You can run the lab, drive a browser and call the API, which means "I believe
this works" is almost never the best sentence available to you. Run it, and
report what came back.

One trap that makes a correct change look broken, covered in AGENTS.md: the UI
is `//go:embed`-ed and needs the control container rebuilt. The browser no
longer needs a hard reload on top of that — the assets carry an `ETag` and
revalidate — but the rebuild is still yours to run.

## The lab on this machine is probably in use

The user very likely has `lab/` running while you work. Read
[the lab may be running, and it may not be
yours](AGENTS.md#the-lab-may-be-running-and-it-may-not-be-yours) before you
reach for `docker`. Narrow commands, restore anything you stopped, and say what
you touched.

## Do not bundle

You will often notice a second problem while fixing the first. One idea per
branch, per [scope](AGENTS.md#scope-one-idea-per-branch). Report the rest; do
not quietly fold it in.
