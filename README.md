# Secure Remote Dev Environment — a guide

A self-contained HTML guide to reaching your MacBook Pro, Linux VPS and Ubuntu
laptop from an iPhone — privately, and without losing work when the connection
drops.

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
| — | `index.html` | The whole picture: four machines, three planes, how the layers stack |
| 01 | Tailscale & WireGuard | Cryptokey routing, NAT traversal, DERP, ACLs, tailnet lock |
| 02 | SSH, keys & hardening | The auth handshake, key types, `sshd_config`, macOS PAM/SACL |
| 03 | Mosh & Blink Shell | Why SSH dies on mobile, the state-sync protocol, Secure Enclave keys |
| 04 | tmux & Herdr | Session persistence, agent multiplexing, the prefix collision |
| 05 | Securing the MacBook Pro | FileVault, port audit, sshd as a launchd daemon, tailnet-only bind, reaching a dev server from the phone |
| 06 | The iPhone client | Device hardening, Blink setup, Mosh, saved hosts |
| 07 | Hardening a Linux VPS | First ten minutes, UFW, closing public SSH, Docker's UFW bypass |
| 08 | The Ubuntu laptop | LUKS, Secure Boot, MAC randomisation, hostile networks |
| 09 | Threat model & key custody | Who you are defending against, blast radius, incident response |
| 10 | Runbooks & checklists | Build order, onboarding, rotation, the full deployment checklist |
| 11 | Troubleshooting | A five-rung diagnostic ladder and a symptom reference |

## Features

- **Interactive diagrams.** Chapters 01–05 carry stepped simulations rather than
  static pictures: pick a scenario, then step through it with the controls or the
  arrow keys. The drawing, the narration and a mock terminal all advance together,
  so you can watch a NAT punch through, an SSH replay get rejected, or a launchd
  job fall into a restart loop. With JavaScript off each one collapses to a
  readable static poster frame.
- **Persistent checklists.** Ticks are saved in `localStorage`, per chapter.
  The full deployment checklist in chapter 10 has a progress bar and a reset button.
- **Dark and light themes**, following your system by default, with a toggle
  (bottom right) that overrides and remembers.
- **Copy buttons** on every command block.
- **Responsive** — genuinely readable on the phone the guide is about.
- **Inline SVG throughout**, themed with the page rather than shipped as images.
- **Printable** — navigation chrome is hidden in print stylesheets.

## Structure

```text
secure-remote-dev-guide/
├── index.html
├── assets/
│   ├── style.css      design tokens, layout, components, SVG theming hooks
│   ├── nav.js         the chapter index — edit here to add or reorder chapters
│   ├── app.js         theme, sidebar, TOC, chapter filter, copy buttons, checklists
│   ├── anim.js        the stepped diagram simulations
│   └── favicon.svg
└── chapters/
    └── 01-…-11-….html
```

`nav.js` is the single source of truth for navigation. Add an entry there and the
sidebar, filter, chapter cards and prev/next links all pick it up. Each chapter
page sets `data-page` on `<body>` to match its `id` in `nav.js`, and `data-depth="1"`
so asset paths resolve.

`anim.js` is opt-in per page — only chapters containing a `<figure class="diagram sim">`
load it. A simulation is declared entirely in markup, with no per-diagram
JavaScript: `data-sim` on the figure, `data-at` to say which step an element
belongs to (`"2"`, `"2+"`, `"0-3"`), `data-scn` to bind it to a scenario button, and
`data-flow` to send dots along a path.

The no-JavaScript fallback is pure CSS rather than script: `anim.js` adds `sim-on`
to the figure when it takes over, and [`style.css`](assets/style.css) hides every
scenario-specific layer *except* those tagged `data-poster` until it does. So
`data-poster` marks the one coherent frame a reader sees with scripting off — worth
setting deliberately on any new simulation.

Chapters 06–11 and the index still use static diagrams and do not load `anim.js`.

Navigation is defined as a plain global rather than fetched, because `fetch()` is
blocked on the `file:` scheme — this is what lets the guide work by double-clicking
`index.html`.

## A note on accuracy

Commands were written against macOS 26, Ubuntu 24.04 LTS, OpenSSH 10.x and
Tailscale as of August 2026. Two things move fastest and are worth checking
against their own docs rather than trusting any guide:

- **Herdr** is young; keybindings and config keys are still settling. Use
  `herdr --default-config` and `prefix + ?` on your installed version.
- **Tailscale SSH** server support is Linux plus the open-source macOS CLI build
  only — *not* the standard macOS app.
