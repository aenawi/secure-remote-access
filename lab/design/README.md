# Design proposals

Things that are not built yet, worked out far enough to argue with.

Nothing in here is served by the control server. `lab/control/main.go` embeds
`ui` and only `ui`, so these files add nothing to the binary and are not
reachable from `http://localhost:8099`. Open them by double-clicking.

## `five-gates.html`

A monitoring HUD for `lab/control/ui`, and the design proposal that explains it.
The prototype is at the top of the page; the reasoning, the data mapping and the
budget are underneath it.

```bash
open lab/design/five-gates.html      # or xdg-open, or drag it into a browser
```

The argument, in two lines: **X is the ladder** — how far a packet travels is the
rung it reached, so you read the answer off the board before you read a word —
and **Y is protection**, with the tailnet floating above the machines and the
public segment lying below, so a packet's height says whether it is wrapped right
now. The lab's current legend already claims the second one (*"the height of the
line is the point"*); this stops making a reader take it on trust.

Every rung becomes a gate that renders its state **continuously, from the
configuration, before any probe runs** — flip `allow 22/tcp from anywhere` and a
slat swings aside and a red beam finds the socket behind it while you watch. That
is the part the current page cannot do: its switches and its picture are eight
hundred pixels and one button press apart.

It is a **model, not the lab**. The ladder engine is a port of
[`assets/sandbox.js`](../../assets/sandbox.js) — same catalog, same grants, same
`choosePath` / `aclCheck` / `firewallCheck` / `listenCheck`, in the same order —
so its verdicts agree with [chapter 14's sandbox](../../chapters/14-sandbox.html)
rather than approximating them. Wiring it to `POST /api/probe`, where a container
answers instead, is the prerequisite for
[issue #24](https://github.com/aenawi/secure-remote-access/issues/24).

### Why it is one 750 KB file

Because the guide works by double-clicking `index.html`, and a proposal that
needs a build step or a web server to read is a proposal nobody reads. three.js
r166 is inlined rather than kept beside the page because
`<script type="module" src="...">` is blocked by CORS on the `file:` scheme.
Nothing is fetched over the network — the type stacks are the ones
[`assets/style.css`](../../assets/style.css) already declares, so JetBrains Mono
is used when it happens to be installed and never requested from anywhere.

three.js is MIT; its notice is preserved at the head of the inlined bundle.

### Where this would and would not live

The HUD belongs in `lab/control/ui`, which is already served by a Go binary doing
`//go:embed ui` — so three.js ships inside the binary, needs no network after
`docker compose build`, and adds no prerequisite to a lab whose only prerequisite
is Docker.

It does **not** belong in `chapters/`. The guide's promise is `file://`, no build,
no dependencies, and a readable figure with scripting off via `data-poster`.
Chapter 14's sandbox stays SVG, and that split is a feature: the model you can
read offline stays a drawing, and the containers you can break get the instrument.
