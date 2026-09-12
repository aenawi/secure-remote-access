# The lab

A disposable network you can break. Real containers, real kernels, real
WireGuard, real packets, and a control surface where every button is a command
that actually runs.

```bash
cd lab && docker compose up -d
open http://localhost:8099
```

Docker is the only prerequisite. No Go, no Python, no npm, no account, and
nothing in the lab needs the internet once the images are built: the
coordination server, both relays and every certificate are the lab's own.

"Needs" is the exact word, and it used to say "no internet connection", which
is stronger than what is true. Two containers sit on bridges Docker gives a
route out of, and `lab-vps` is one of them — measured, with a tunnel open,
in [what still has a route out](#what-still-has-a-route-out). The
one that matters is `evil-box`, and that one is measured too: it reaches the
lab's bridges and nothing else. The section below is what it can and cannot
touch.

The guide ships two versions of this network.
[Chapter 14](../chapters/14-sandbox.html) simulates it in your browser; that one
is **the sandbox**. This directory builds it for real, in containers; that one
is **the lab**. Same panel names, same button labels, same output format, so if
you can drive one you can drive the other blind.

What differs is what each can tell you. The sandbox can only show you what
somebody modelled. The lab has no model, so it can surprise you. It has
surprised us more than once, and every surprise is written up below, with what
we measured and which of the two we then corrected.

---

## Safety, before anything else

`evil-box` attacks containers you started, on hardware you own, on bridges
that go nowhere. It is behind a compose profile and does not exist until you
ask for it with `--profile attack`. Its network reaches the other lab
containers and nothing else: not your LAN, not your router, not the internet.

That is measured rather than asserted, and it was measured again when tailcat
put a second relay on the shared segment, because a relay is exactly the kind
of thing that quietly becomes a way out. From `evil-box`, with the relay up and
a tunnel open:

```
ping 1.1.1.1                    no route
tcp  1.1.1.1:443                no route
https tailcat.dev               no route
your LAN 192.168.x.1            no route
docker0 172.17.0.1              no route
the lab's relay 203.0.113.3     reached
```

What keeps it in is the routers, not a firewall on the machine: `images/nat`
ends its `FORWARD` chain with `-j DROP`, and the only thing it accepts is
`lan → wan`. So a packet from `evil-box` to anywhere that is not the lab has
nowhere to be forwarded. The relay changed none of that, and it runs with
`net.ipv4.ip_forward: 0` so that it cannot become the exception.

One thing it does reach, because every Docker bridge works this way: the
host's own address on the bridge it is attached to. That is the gateway
Docker created, it is how the container has a network at all, and there is
nothing listening on it from the lab.

### What still has a route out

The attacker has no way out. Two other containers do, and this file used to
say otherwise, so it is worth saying exactly which and why.

`lab-vps` and the three routers sit directly on bridges Docker gave a default
route, and Docker masquerades those subnets onto whatever network your machine
is on. Measured, on a lab with the relay up:

```
lab-ubuntu   no internet     behind nat-ubuntu, whose FORWARD chain drops it
lab-roam     no internet     behind nat-roam, the same
evil-box     no internet     behind nat-evil, the same
lab-vps      reaches the internet
```

`lab-vps` is the one machine in this lab with a public address of its own,
which is the whole of its problem and the reason it is on the shared segment
rather than behind a router. Being on that segment is what gives it the route.

Nothing in the lab uses it. Every certificate is minted locally, both relays
are local, the coordination server is local, and `tailcat` never fetches a DERP
map because the relay is baked into the address — which is why the two machines
with no internet at all run the tunnel perfectly well. So this is a claim this
file had wrong rather than a capability anything depends on, and the honest
version is the one at the top: nothing here *needs* the internet.

If you want it closed rather than described, `internal: true` on the `wan`
network is the change, and it is left undone on purpose: it is a real
behaviour change to a segment that stands in for the public internet, and
making the pretend internet unable to reach the real one is the kind of thing
that should be somebody's decision rather than a side effect of a ticket about
tunnels.

The control server holds `/var/run/docker.sock`, which means anything that can
talk to it can run commands as root on your machine. It therefore:

- has no authentication, because nothing off this host can reach it;
- is published to `127.0.0.1:8099` only;
- reads its own port bindings at startup and refuses to run if it finds
  itself published anywhere else.

Do not change that `ports:` line. If you do, the server will tell you why it is
not starting.

Everything here is provided as is, with no warranty of any kind, under the
[GPL-3.0-or-later licence](../LICENSE). The full terms and the reasoning behind them are in
[the disclaimer](../index.html#disclaimer). Practise here; do not paste the
generated script at a machine you rely on without reading it first.

---

## What you get

```
docker compose up -d
```

| Service | Role | Notes |
|---|---|---|
| `control` | The Go control server and its embedded UI | mounts the Docker socket, binds `127.0.0.1:8099` only |
| `headscale` | Coordination server **and** the tailnet's DERP relay | one process, two roles; see the Headscale section |
| `derp` | tailcat's relay, and the one with nothing behind it | `derper`, on the shared segment, holding no policy and no identities |
| `lab-vps` | The public box ([chapter 08](../chapters/08-vps.html)) | `tailscaled`, `sshd`, `ufw`, and the published-port trap |
| `lab-vps-web` | The container behind the published port | reachable only through `lab-vps`, and only when you turn the trap on |
| `lab-ubuntu` | The laptop ([chapter 09](../chapters/09-ubuntu.html)) | `tailscaled`, `sshd`, `mosh` |
| `lab-roam` | The roaming client ([chapters 03](../chapters/03-mosh-blink.html) / [04](../chapters/04-tmux-herdr.html)) | behind a deliberately unfriendly NAT |
| `nat-ubuntu`, `nat-roam`, `nat-evil` | One home router per machine | masquerade only, no port forwards |
| `evil-box` | The attacker | `nmap`, `tcpdump`, `tcpreplay`, `hping3`, `dsniff`, `wireguard-tools`. **Opt in with `--profile attack`** |

### The shape of the network

```
lan-ubuntu 10.0.13.0/24 --[ nat-ubuntu 203.0.113.13 ]--\
lan-roam   10.0.27.0/24 --[ nat-roam   203.0.113.27 ]---+-- wan 203.0.113.0/24
lan-evil   10.0.66.0/24 --[ nat-evil   203.0.113.66 ]--/      |
                                                              |- headscale 203.0.113.2
                                                              |- derp      203.0.113.3
                                                              |- lab-vps   203.0.113.11
```

Every machine sits on its own segment behind its own router. That is the point
and it is not decoration: if they all shared one bridge, "NAT traversal" would
be a word rather than a thing that has to happen, and
[chapter 01](../chapters/01-tailscale.html) would be untestable here. The
addresses on the shared segment are RFC 5737 documentation addresses, so
nothing in this lab can be mistaken for a real host.

`nat-roam` runs with `MASQUERADE --random`, which allocates a fresh source port
per destination. That is an endpoint-*dependent* mapping, the unfriendly kind,
the kind a phone on mobile data often gets, and it is why `lab-roam` is the
machine that falls back to the relay first when anything else goes wrong.

---

## Driving it

Everything below is one click in the UI. The command shown is what actually
runs, and the **script** tab collects them all in order so you can paste them at
the three Lima VMs in [chapter 13](../chapters/13-lab.html).

### The layout

The page is one instrument, not a document you scroll. It is three bands, and
none of them moves relative to the others:

- **the drawing**, pinned to the top of the window: drag the divider under it
  to give it more of the window or less, double-click to put it back, or focus
  it and use the arrow keys;
- **the verdict**, one line directly under the drawing that produced it;
- **the deck**, two columns that scroll independently: everything that
  *changes* the lab on the left, one group per tab, and everything the lab
  *said back* on the right, including this page's own documentation, in the
  **guide** tab, which is what opens on a first visit.

The point of the arrangement is that flipping a switch and reading what it did
no longer costs you sight of the picture that changed. Below 1000px wide, or on
a short window, it falls back to an ordinary scrolling page with the drawing
stuck to the top of it and both tab strips intact.

### The picture

Two drawings of the same lab, and a switch in the top bar that picks one.

**The board** is the five-rung ladder from chapter 12 rebuilt as a place a
packet has to travel through. X is the ladder: how far something got is
the rung it reached. Y is protection, with the tailnet floating above
the machines and the public segment lying below, so a packet's height says
whether it was readable while it went. Every gate on it renders the
configuration continuously: turn `allow 22/tcp from anywhere` off and a slat
swings shut while you watch, with nothing probed.

Each of the ten attacks gets its own camera move and its own single claim on
it, driven by the fields on the `Result` the server returned. Run the same
attack against `weak` and against `hardened` and the frame differs, because
the numbers differ. Two of them light objects rather than prose: `scan-public`
puts one lit dot on lab-vps's face per port `nmap` actually reported open, and
`sniff` drops the marker sent in the clear and the identical marker sent
through the tunnel into a tray as two different objects. Both read those
counts from `Result.Evidence`, which exists so that a drawing never has to
regex English to find a number the Go side already had.

**ssh and mosh, through a 20-second outage** has a set-piece as well, and it is
the only one with two acts. The blackout resolves and says what it proved
before the roam starts, because the whole lesson is that the first act does not
do what everybody expects it to, and that only reads if you are allowed to
finish being surprised by it before the second act begins.

So does **Rotate the key**, and it is the odd one out: nothing is attacking
anything, and nothing is defending. Rotating a node key is maintenance, and
maintenance is judged by what it does *not* disturb, so the claim is
continuity, in three parts. The coordination server stops holding the key it
held; the machine stays inside the tailnet at the same address; and a session
running over that address does not notice. Each part is measured, and each has
an ending where it was not: a run that re-keyed nothing draws no re-key and
says so instead. Unlike the outage demonstration this one runs over the
**tailnet** address on purpose, so its lane rides up in the tailnet plane. A
rotation a session cannot feel even in principle would prove nothing about the
rotation.

The board holds to four rules, and they are why it is worth trusting:

- Nothing is drawn that was not measured. An empty capture draws an empty
  tray and says the run proves nothing either way, because a successful
  capture is the interesting picture and that is exactly why it must not be
  animated when there was not one.
- A failed attack is not a green tick. `ok` on an attack means the defence
  held; the shot renders the defence answering, and names it.
- `danger` outranks `ok` in tone. `docker-bypass` succeeding is a red frame.
- Time is not faked. The choreography is a fixed length. The millisecond
  figures stay the measured ones.

It needs WebGL, and it is decoration you can switch off: every state it shows
is also in the readouts above it and in the **packets** tab, the verdict goes
to a live region, and the canvas itself is `aria-hidden`. With
`prefers-reduced-motion` set, the camera holds the final frame instead of
flying to it and the words are identical. If WebGL is unavailable the page
falls back to the flat drawing and says so once.

**The flat drawing** is the original, and it stays: the same picture chapter 14
draws, with the simulation taken out of it. Every address on it was read back
from a container, and the shape of the line is whatever `tailscale ping` last
reported:

- straight across the middle: direct, the punch completed;
- bending up through the box in the centre: relayed through DERP;
- dipping into the red band: it crossed the public segment, and the band
  lights up to say so.

Before you probe anything it says **idle · run a probe**, and it means it. An
idle Tailscale peer reports no current address, which looks exactly like a relay
if you take it at face value; saying "relay" about a pair that has simply not
spoken yet would be the most misleading thing this page could do. So it waits
until there is something true to draw.

### Panels

Five, with the same names and the same switches as the sandbox, one tab
each in the left column, labelled with the panel's id, so a panel added to
`panels.go` becomes a tab without anything in the UI being told its name:

- **Machines**: who is running, who the tailnet will accept, and whether
  `evil-box` is sitting on `lab-ubuntu`'s segment.
- **The network**: the three levers chapter 13 shapes by hand: `ip link`,
  `tc netem` loss and delay, and an `nft` rule dropping WireGuard's UDP port.
- **Tailnet policy**: the default action, four named grants, tailnet lock,
  key expiry, Tailscale SSH.
- **The host — lab-vps**: `ufw` defaults and rules, the published container
  port, `sshd`'s `ListenAddress`, `PasswordAuthentication`, `PermitRootLogin`.
- **Tailcat — the escape hatch**: whether somebody ran `tailcat serve`, on
  which machine, serving what, whether `--allow` pins a client key, and
  whether the address reached `evil-box`. Nothing on it is part of the build.
  It is the one panel the lab does not have to be told about: four of its five
  switches are read back off a running process, so a tunnel somebody starts by
  hand shows up here without anybody pressing anything. See
  [The escape hatch](#the-escape-hatch).

### Probe

The probe never answers yes or no. It answers which rung, using the same
five-rung ladder [chapter 12](../chapters/12-troubleshooting.html) teaches, and
unlike the sandbox, it works the rung out from evidence rather than from a
model:

1. Is anything alive? Containers, links, tailnet sessions.
2. Is there a path, and is it direct or relayed? Answered by `tailscale ping`,
   which keeps trying until it gets a direct path or runs out of attempts, so
   what you see is the path the two machines settle on.
3. Did the tailnet allow it? The probe starts a `tcpdump` on the destination
   before it knocks. If nothing arrives, the tailnet refused it, and the
   far machine has no log line to show you, which is exactly how a rung-3
   denial feels when you are debugging one at three in the morning.
4. Did the host firewall allow it? Something arrived and then died: visible on
   the machine, unlike rung 3.
5. Was anything listening? Something arrived and was refused. Usually a bind
   address, not a rule.

Round-trip time and loss come from `ping`; packet and retransmit counts come
from the kernel's own `nstat` counters around a 2 KiB transfer. They are
measurements, not arithmetic.

### Attacks

Ten buttons, the same ten as the sandbox, and each one ends by naming the
defence that answered it. The tenth is the odd one and says so: it names the
defences that were never asked.

| Attack | What it actually does | What it proves |
|---|---|---|
| Scan from the open internet | `nmap` from `evil-box` at `lab-vps`'s public address | what a stranger sees with no credentials |
| Scan from inside the tailnet | joins `evil-box`, then probes all three machines | membership is not authorisation, unless you left it that way |
| Sit on the wire and capture | puts `evil-box` on `lab-ubuntu`'s route and runs `tcpdump` | see below: this one has a control experiment in it |
| Replay a captured frame | `tcpreplay` of the captured WireGuard frames, 20 loops | the receiving kernel discards every one |
| Join with a stolen node key | `tailscale up` on `evil-box` with a key it should not have | what a leaked key is worth, with and without something vouching for it |
| Let a key expire | `headscale nodes expire` on `lab-roam` | the lost phone that removes itself |
| Advertise a rogue exit node | `tailscale set --advertise-exit-node` on `evil-box` | an exit node is a route *offer*; approval is separate from membership |
| Publish a Docker port | writes the chains dockerd writes, then curls from outside | UFW says deny; the port answers anyway |
| Open a tailcat tunnel from the inside | runs `tailcat serve` on one of your machines and connects to it from `evil-box` | nothing you configured is consulted, because none of it is asked |
| Run the build order wrong | deletes both the public and the tailnet `ufw` rules | the lock-out, on a machine you can afford to lose |

Two more buttons sit underneath: **ssh and mosh, through a 20-second outage**
and **Rotate the key**. The first of those is the session layer rather than the
network layer, and it is the one demonstration on the board that runs at
lab-vps's **public** address on purpose, so both sessions are encrypted and
neither is up in the tailnet plane, which is what the shot says while it runs.
The sandbox carries that one as well now, under the same label and in the same
place; what its half does instead of measuring is written up
[with the finding](#the-sandbox-has-this-now-too-and-here-is-exactly-what-it-does-instead).
**Rotate the key** is still only here.

The second is maintenance, and it has two situations. If `lab-roam` is a member
it opens an ssh session over the **tailnet** address, forces the re-auth
underneath it with `tailscale up --force-reauth`, and reports whether the
session kept counting: the tick it had reached before, and the one it reached
after. If `lab-roam` is out, usually because **Let a key expire** just put it
there, there is nothing to keep, and the demonstration is instead that one
command and the key you already had bring it back. Either way it reads the node
key the coordination server holds before and after, so "it re-keyed" is
something the run found rather than something the button claims. It takes about
a minute.

#### Every attack that crosses the public segment measures the route first

`make attack` creates two containers, not one: `evil-box` and `nat-evil`, the
router that carries its packets off its own segment. Stop the router and the
attacker keeps running, keeps its default route, and reaches nothing —
`ping 203.0.113.3` to the lab's own relay is 100% loss while
`docker ps` and `/api/state` both still say `online`.

That state used to score. `nmap` prints `filtered` both for "a firewall dropped
this" and for "nothing carried this", and at rung 4 there is nothing else to
tell them apart, so **Scan from the open internet** answered a stopped router
with `ok`, rung 4 and `ufw default incoming policy: deny` — byte for byte the
verdict a run where the firewall really did the work gets. Measured on Docker
29.7.2 on 2026-09-12, and it was the same for the other six attacks that have
to leave that segment, and for five of the eleven audit checks, where five
failures to reach read as five passes.

So the precondition is no longer "the attacker's container is running". Before
any of those seven scores, one packet goes from `evil-box` to the relay at
`203.0.113.3`, and a run that gets no answer refuses at rung 1, naming the
router rather than a defence:

```
{"ok": false, "rung": 1, "rule": "nat-evil is stopped",
 "why": "The attacker's own router is down, so it reaches nothing at all — not
         lab-vps, not the coordination server, not the relay. Its route survived
         the outage; the gateway at 10.0.66.254 did not. …"}
```

The relay is the target on purpose: it sits on the public segment, holds none of
your firewall rules, and no configuration in this lab changes it. Aiming at
`lab-vps` would ask two questions in one packet. The router is not restarted for
you either — a stopped router is a network condition, like a downed link, and
this lab's job with those is to measure them. The one control that does put it
back is `evil-box`'s own switch in the **Machines** panel, which brings up the
pair and says so, and `/api/state` now carries `routerDown` for any machine
whose NAT box is stopped, which the drawing dims and labels.

**Sit on the wire and capture** and **Replay a captured frame** are the two that
still ask only for `evil-box`, because `nat-evil` carries none of their packets:
both work on the segment `evil-box` already shares with `lab-ubuntu`.

#### The capture has a control experiment in it

"We captured the traffic and could not read it" proves very little on its own:
a broken capture looks identical. So the lab sends the same marker string twice
while `tcpdump` is running: once in the clear over UDP, once through the tunnel
inside WireGuard. Then it counts both in the raw capture file.

A good run reports something like:

```
cleartext=1
tunnelled=0
frames=86
```

The marker sent in the clear is right there in the bytes; the identical marker
sent through the tunnel is not, in 86 frames of genuine ciphertext. If the
cleartext count were also zero the result would be meaningless, and the lab says
so rather than claiming a win.

### The escape hatch

The tenth button is the only one that does not attack the network, and the
only one whose interesting output is a list of things that did not happen.

Somebody on the inside runs `tailcat serve`. Not an attacker breaking in — a
contractor, a process, a well-meaning admin who wanted a quick way through. No
account, no root, no daemon, nothing registered with anything: one static
binary that prints an address, and whoever holds that address can connect.
[Chapter 01](../chapters/01-tailscale.html) has the rest, including why the
address is a bearer credential and why ephemeral is the right default.

The perimeter is untouched and still passes every audit check. What the run
measures is which rungs of the ladder were consulted, and the answer is that
two of them were not, because nothing asked them:

- **Rung 3 · the tailnet policy.** There is no control plane over tailcat, so
  there is no grant to match and no default action to fall back to. The
  readout shows the tunnel's own socket: one connection out, to the relay,
  and none at all to the coordination server.
- **Rung 4 · the host firewall.** The listener is reached over a connection
  the serving machine *dialled out*. An inbound default-deny never sees it,
  and `tcpdump` on that machine says so — it watches its own interface for an
  inbound SYN to `:22` for the whole run and catches nothing. UFW is
  untouched, still correct, and was never in the path.

"The firewall was bypassed" would be the wrong sentence and the lab can show
it is wrong, which is the difference between this half and the model.

Two more things get measured because a model could not have told you either.
Whether the two ends punched **direct** or stayed on the relay:

```
lab-ubuntu   pong in 650µs via 10.0.13.2:51899     direct, over the shared segment
lab-vps      pong in 360µs via 203.0.113.11:53538   direct, over the public segment
lab-roam     pong in 1.7ms via DERP(1)              relay only, after 20s of trying
```

Read the first one for what it is. `evil-box` has an interface on
`lan-ubuntu` — the optional shared segment the **Machines** panel switches
routing onto — so a direct path to `lab-ubuntu` is a hop across a wire they
both sit on rather than a punch through two NATs. The second is a genuine
punch to a public address. The third is the interesting one: `lab-roam` is
behind `nat-roam`, which allocates a fresh source port per destination, so
nothing punches, and the tunnel works anyway, over DERP, at the same rung.
That run takes about half a minute because `tailcat ping --until-direct`
spends twenty seconds failing to do the thing it is being asked to prove
cannot be done here. And whether anything answered at all
versus whether anybody got a **shell**, which come apart cleanly here: the
address gets you to a door on every service, and only `no-auth-ssh` has taken
the lock off it.

`--allow` is the one switch on that panel that puts an identity back in the
path, and "evil-box was refused" does not on its own show that — a tunnel that
had simply broken would look identical. So the pin has a control experiment,
the same shape as the capture's control marker: the machine whose key is
pinned is asked to connect too. Both halves have to hold, or the run reports
that it proved nothing.

### The relay tailcat uses, and why it is not the other one

Tailcat needs a DERP relay to find its peers, the public ones are on the
internet, and this lab is meant to need none. So the stack has a second relay:
a real `derper`, pinned and built from source, on the shared segment at
`203.0.113.3`, answering to `derp.lab.internal` with a certificate the control
server mints from the CA the machines already trust.

`tailcat genkey --region=derp.lab.internal` bakes that hostname into the
address, so neither end ever fetches a DERP map from anywhere — which is what
keeps the lab offline and keeps a container in an attack profile from having a
reason to talk to `tailcat.dev`.

The coordination server already embeds a DERP relay and still does, and that
one is the tailnet's. Tailcat cannot use it for a mechanical reason and should
not for a better one:

- **Mechanically**, an address built from a hostname carries a hostname and
  nothing else, so its client dials `:443` and the standard `/derp` path.
  Headscale's relay answers on `:8443`, beside the coordination API, and there
  is no tailcat flag that reaches it without hosting a DERP map for both ends
  to fetch.
- **The better reason**: chapter 01's claim about tailcat is that it is the
  data plane with the control plane taken out. Sending its packets through the
  container holding the ACLs, the node keys and the expiry dates would undercut
  that claim in the one place a reader would look to check it. `derper` has
  nowhere to put a policy. That is the property under test.

The command the lab runs is in the **script** tab like every other, and it is
not quite the one chapter 01 prints — see
[finding 8](#8--the-command-chapter-01-prints-is-not-the-command-that-runs).

---

## Named configurations

The same four ids as the sandbox, with the same meanings, as compose profiles:

```bash
docker compose --profile day-one  up cfg-day-one    # or: make day-one
docker compose --profile typical  up cfg-typical
docker compose --profile weak     up cfg-weak
docker compose --profile hardened up cfg-hardened
```

Each one runs the same code the button in the UI runs: one binary, one code
path, so the two cannot drift apart.

Then score it:

```bash
make audit          # or press "Audit this configuration"
```

Eleven checks, the same eleven as the sandbox, with the same labels and the same
rubric. The only thing that changed is how each one is answered: there it asks a
model, here it asks a container. Two of the eleven ask whether *you* can still
get in. They are not padding: without them, a machine you have locked
yourself out of scores nearly perfectly and "closed" reads as "secure".

The audit takes about a minute, because five of the eleven really do join and
unjoin the attacker. It needs `evil-box`; without it the lab refuses to produce
a score rather than reporting one with five holes in it.

There is no twelfth, and the tunnel above is why there could have been one.
A container can be inspected for an unmanaged tunnel process — this lab does
exactly that, four switches' worth, on every observation — so *"no unmanaged
tunnel process is listening"* is a check this half could honestly answer. The
sandbox cannot: only a real host can be inspected for a process, and a model
would be scoring its own memory of a switch.

Eleven is a rubric shared one-for-one, and two halves scoring differently on a
check only one of them can run would be worse than not having the check. So it
is a banner above the list rather than a number in it, it moves no score, and
it says so. If a twelfth is ever added it goes into both halves in the same
change.

The banner is also where the two halves stop agreeing about how blind the
score is, which is [finding 5](#5--the-sandbox-score-moves-a-little-this-one-does-not-move-at-all).

One check is marked: this lab answers it for you, whichever way it goes, and
the readout says so rather than letting you take the credit or the blame. It
still counts in the score, because a number that argues with what was measured
is worth nothing, and the mark only changes what is said about it. Today it is
**"A lost device stops being a member on its own"**, and the mark reads *cannot
fail here*: Headscale records an expiry on every registration and offers no
switch to turn one off, so three of the four configurations pass it while asking
for it to be off. See the next section for why that is a finding and not a
detail.

---

## Where this lab and the sandbox disagree

This is the most valuable part of the directory. When the sandbox and the lab
give different answers, one of the two is wrong about how the real world
behaves, and finding those was the whole reason for building both.

Eight disagreements are recorded below, and three of them are closed. Twice the
sandbox was wrong and we corrected the sandbox. Once both were wrong in the same
way, arrived at from opposite ends, and we corrected both. Finding 1 we closed
neither way: Headscale shipped the feature the gap was made of, and closing it
opened a new gap pointing the other direction, which is why that one is still
here and still open.

Findings 5 to 8 are the newest, they all came from the same week's work — the
escape hatch arriving in containers after a year of being only a model — and
all four are deliberately open. Every one of them is the containers correcting
the model, and the rule for that is written into the ticket they came from:
write the disagreement down rather than filing the model into agreement.

Which way a disagreement points is not decided in advance. Neither half is the
reference the other gets checked against, and that is the reason to keep both.
Closed ones stay in this file rather than being deleted: what was measured, and
when, is worth more later than the fix that followed it.

Everything in this section is an observation about one build of one stack.
The coordination server is pinned (`headscale/headscale:0.29.3` in
[`docker-compose.yml`](docker-compose.yml)) and the tailscale client is not: the
machine image installs whatever `stable` holds when you build it, which was
1.102.3 for the runs below. Each finding says what it was last measured against.
A divergence is a fact with a date on it rather than a property of the world,
and finding 1 is in this file precisely because it was once written without
one.

Both columns below were measured, not derived. The sandbox scores come from its
own comparison table, the lab scores from `make audit` against each profile:

| Configuration | Sandbox | This lab | Why they differ |
|---|---|---|---|
| `day-one` | 4/11 | **5/11** | key expiry (1 below); was 3/11 in the sandbox, see 2 |
| `typical` | 4/11 | **5/11** | key expiry (1 below) |
| `weak` | 2/11 | **3/11** | key expiry (1 below) |
| `hardened` | 11/11 | 11/11 | — (was 10/11 here; see 1 below) |
| the boot state | 8/11 | 8/11 | — (was 7/11 here; see 1 below) |

Those five lab scores are not decoration. `make check` parses this table and
asserts it against a checked-in fixture of which of the eleven each
configuration passes, so a number here and the number `audit.go` computes
cannot drift apart without a failing test naming both.

Every gap in that table is still the same single divergence, key expiry, but
it has changed sides. It used to cost this lab a point on the two configurations
that asked for expiry *on*; it now hands this lab a point on the three that ask
for it *off*. Apart from that one check, the sandbox and the lab fail the same
checks in all five configurations. Five more gaps show up when you drive the
lab rather than score it, and one of those — finding 5 — is about a score that
does not move when the sandbox's does. All eight are below.

### 1 · Key expiry, which used to cost this lab a point and now gives it one

Open, and it changed sides. The check is **"A lost device stops being a
member on its own"**, and it has been the only real divergence in the table for
as long as the table has existed. What it says about the sandbox and the lab is
now the opposite of what it used to.

What it was, up to Headscale 0.26.1. Headscale recorded a node expiry only
when the registration asked for one, and a pre-auth-key registration did not,
so `headscale nodes list` showed `Expiration: N/A` for all three machines and
one could not be added afterwards. `hardened` scored 10/11 here against 11/11 in
the sandbox, and this file said, in as many words, that the gap was permanent
and should be left alone.

It was not permanent. The upstream bug was
[juanfont/headscale#1711](https://github.com/juanfont/headscale/issues/1711),
and 0.29.0 closed it by adding a `node.expiry` configuration key that sets a
default expiry for nodes registered via auth key. That is a missing feature,
shipped, not an architectural difference between Headscale and Tailscale, which
is what this file had claimed it was. The lab pins `0.29.3` and
[`config/headscale/config.yaml`](config/headscale/config.yaml) sets
`node.expiry: 4320h`, which is Tailscale's 180 days.

And that setting does not reach these three machines. It was written down
here as though it did, and for a while this file and the containers disagreed
about the reason the check passed, which is the exact failure mode the lab
exists to catch, caught on the lab itself. Measured on 0.29.3: a node registered
with a *single-use* pre-auth key comes back from `headscale nodes list` with an
expiry 180 days out, and a node registered with a `--reusable` one comes back
with `Expiration: N/A`. This lab mints a single reusable key and every machine
reads it from `/lab/state/authkey`, so all three landed in the second case and
check 10 failed even under `hardened`.

Sharing one key is worth keeping, because a per-machine single-use key would
have to be reissued on every rejoin, and rejoining is what half the buttons here
do, so the expiry is stamped on afterwards instead. `EnsureNodes` in
[`control/state.go`](control/state.go) runs `headscale nodes expire -e <RFC3339>`
against any owned node that has none, alongside the tag it already applied. It
stamps only when the field is empty, which keeps it idempotent and keeps it out
of the way of **Let a key expire**, which sets an expiry in the *past* and would
otherwise be undone a second later. All three machines carry a real expiry, the
check passes, and `hardened` and the boot state agree with the sandbox at 11/11
and 8/11. The `node.expiry` setting stays: it is correct, it costs nothing, and
it takes over if these keys ever stop being reusable.

And that opened the mirror image of the old gap. Headscale still has no
per-node "disable key expiry", and neither does this lab's stamp: it applies to
every registration and nothing in a configuration turns it off. `day-one`,
`typical` and `weak` all ask for expiry to be *off*, and get it anyway, and
score a point for it that the sandbox does not give them. That is why those
three rows are now the ones in bold.

The audit says so on the check rather than leaving it to this file. Its rule
line reads *"the control server stamps one on at registration and Headscale
offers no per-node way to turn it off, so this one holds whatever the
configuration says"*, and the check is marked **cannot fail here** in the same place the old
one was marked *cannot pass here*. The score counts it as a pass either way,
because the alternative is a number that argues with what was measured, but a
tick nothing you did produced is the more misleading of the two marks, and it is
the one the readout leads with. Turning **Key expiry** *off* in the UI still
returns a typed refusal explaining that Headscale has no such switch, which is
the same fact met from the front.

What still works, and is worth doing: **Let a key expire** calls
`headscale nodes expire` and you can watch `lab-roam` fall out of the tailnet on
its own within seconds. That is a real failure of this check when it happens,
and it is *not* marked: it is a state somebody produced rather than one the lab
decided.

This is still the gap to leave alone, for the same reason as before: closing it
would mean the sandbox modelling Headscale's limitation rather than Tailscale's
behaviour, and the guide is about Tailscale. What was wrong was never the
decision. It was calling it permanent. Measured against Headscale 0.29.3.

### 2 · Nobody can reach your laptop from the internet, and the sandbox thought they could

Closed. When this was found, `day-one` scored 4/11 here and 3/11 in the
sandbox. The two agree at 4/11 now, and this lab reads 5/11 for the unrelated
reason in finding 1. The extra pass was **"…nor your laptop"**, checked with the
tailnet switched off entirely.

The sandbox gave every machine a public address and let a public path find one,
so an attacker on the open internet reached `lab-ubuntu:22`. In the lab it
does not, and cannot: `lab-ubuntu` lives on `10.0.13.0/24` behind `nat-ubuntu`,
which masquerades outbound and forwards nothing inbound. There is no address for
a stranger to aim at. The probe says so at rung 2 rather than inventing a path.

That is what a laptop behind a home router actually looks like, and it is worth
knowing which of the two you have been picturing. It is also the one finding
here that no version bump can move: it is the lab's own topology, not a
behaviour of anything shipped. The sandbox now models it the same way: a machine
with a NAT in front of it has no inbound address, and a probe aimed at one stops
at rung 2 naming the router that swallowed it. It also does not let the
configuration off the hook: the moment the laptop joins a tailnet, it becomes
reachable from every other member, and checks 6 and 7 are what watch that. The
sandbox says so out loud on that check now, so a pass earned by a home router
does not read as a pass earned by your policy.

### 3 · Blocking UDP does not make `netcheck` say `UDP: false`

Closed. The sandbox showed `tailscale netcheck` reporting `UDP: false` when
you dropped WireGuard's port. The real thing does not, and it is right not to:
`nft ... udp dport 41641 drop` blocks WireGuard, while `netcheck` probes UDP
reachability using STUN on port 3478, which is still open. What *does* change,
within a few seconds, is the path: `direct` becomes `relay`, exactly as the
chapter says.

A network that really does block all outbound UDP would report `UDP: false`.
This lab blocks the port [chapter 13](../chapters/13-lab.html) tells you to
block, because the generated script has to be the script that chapter runs.

The sandbox now prints `UDP: true` with the port dropped, and says in the
readout why the two lines disagree, which is a better lesson than the one it
replaced, and it came from running the command rather than from reasoning about
it. Measured against tailscale 1.102.3, and this is a client-side reading:
which port `netcheck` probes is the client's business, and a future one could
change it.

### 4 · A key the tailnet refuses is still a machine on the internet

Closed, and we changed both. Each had the same bug, arrived at from the
opposite end.

The sandbox used to stop an unsigned or expired node key at rung 1, which meant
tailnet lock refused traffic it has no say over: an ordinary TCP connection to
a public address, nothing to do with the tailnet at all. Lock and expiry now
decide *membership* there: a refused node is simply not on the tailnet, so it
falls through to the ordinary network and reaches whatever is publicly
reachable.

This lab had the same bug, arrived at from the other end. Its **Tailnet lock**
switch is "does a key exist for a machine you did not authorise", so with it on
`evil-box` cannot join at all, and `audit.go` used to report the check refused
at rung 1 without probing, rather than asking what `evil-box` reaches *without*
a tailnet session. `Probe` had modelled it correctly all along; the audit simply
never called it on that path. So tailnet lock was taking credit for a public
`:22` that UFW had left wide open.

Both are fixed, and the lab settles it. With lock on, `:22` open and
`sshd` on `0.0.0.0`, **Join with a stolen node key** now reports:

```
evil-box → 203.0.113.11:22        rung 5/5     path: public
Connection to 203.0.113.11 22 port [tcp/ssh] succeeded!

lab-vps saw it arrive:
08:21:49.001182 IP 203.0.113.66.49588 > 203.0.113.11.22: Flags [S], …
```

That is `tcpdump` on `lab-vps` watching the SYN land while `evil-box` knocks:
the key was refused and the packet arrived anyway. Close public `:22` and the
same attack stops at rung 4. **Let a key expire** behaves identically:
`lab-roam` drops out of the tailnet on its own and still reaches `sshd` at rung
5, until the public rule is gone.

Re-scoring after the fix cost this lab's boot state a point. The extra failure
is **"A stolen node key is refused"**, which is now honest. The four named
configurations did not move, `hardened` included, because `hardened` had already
closed public `:22`. The sandbox moved the same way, 9/11 to 8/11. (The boot
state read 7/11 for a while afterwards and reads 8/11 today; the point it got
back is finding 1's, and has nothing to do with this one.)

The lesson underneath is worth more than the score. Tailnet lock decides who is
a *member*. Closing public `:22` decides who can reach the *machine*. Neither
substitutes for the other, and for months both the sandbox and the lab implied
that tailnet lock did the firewall's job.

Re-measured against Headscale 0.29.3, and it holds: the boot state still
fails **"A stolen node key is refused"** for the same reason, which is why that
row reads 8 and not 9.

### 5 · The sandbox score moves a little. This one does not move at all.

Open, and it is the reason the tunnel is a banner in both halves rather than a
number in either.

The sandbox's own banner is careful about this, and it is right about itself: a
tunnel on `lab-vps` drops its score to 7/11 and one on `lab-ubuntu` to 10/11,
because some of the eleven happen to probe those machines, while the same
tunnel on `lab-roam` leaves a clean 11/11. A score that moves only when the
attacker's route happens to cross a check is a better lesson than blanket
blindness, and the sandbox says so.

None of that happens here. Load `hardened`, score it, then run
`tailcat serve no-auth-ssh` on `lab-vps` and hand the address to `evil-box`.
Measured:

```
11 / 11 checks held
evil-box → tailcat ssh root@tc…      rung 5/5      a root shell
lab-vps saw no packets arrive inbound on eth0:22 in the whole run
the same probe, the ordinary way:    rung 4/5      ufw dropped it
```

Eleven out of eleven, with a stranger holding a root shell, and the score is
not one point lower — whichever machine is serving.

The reason is the difference between a model and a stack. The sandbox's
`choosePath` answers for tailcat *before* the ordinary network gets a turn, so
any probe aimed at the serving machine takes the tunnel and some checks notice.
In this lab every one of the eleven aims `nc` at an address, and a tailcat
address is not an address: it is a bearer credential parsed by one client, and
no `nc` anywhere can reach a tailcat server. There is nothing for a check to
stumble over.

Neither half is corrected, because neither is wrong about itself. What it
changes is the sentence the banner leads with, and the lab's is the more
alarming one: not a number that drops, a number with nothing to say.

Measured against tailcat 0.6.0.

### 6 · `serve all` reaches the machine's own sshd, and it still wants a key

Open. The sandbox reports `serve all` as a way in: its rung-5 check answers
"tailcat serve all, proxying straight through to :22", the probe succeeds, and
the verdict says *evil-box has a shell*.

Here it reaches a door and stops at it. `serve all` really does put every port
on the machine behind the address — `evil-box` gets an SSH banner back through
the tunnel, from `lab-ubuntu`'s own `sshd`, which is exactly what "all" means.
And that `sshd` then asks for a key `evil-box` does not have, because it is an
ordinary daemon with no idea any of this happened.

Both are defensible readings of a five-rung ladder and they are answering
different questions. Rung 5 is "was anything listening", the sandbox answers
that, and by that measure it is right. The lab can answer the next question
too, so it does, and it keeps the two apart in the verdict rather than letting
"the port answered" read as "somebody got in".

Which matters more than it sounds, because the mitigation is not tailcat's:
what refused `evil-box` was chapter 02's key policy, on one service. Every
other port that machine happens to open is behind the address with whatever
lock it already had, which for most things is none. The lab's wording says
that; "evil-box has a shell" would have credited tailcat with a defence it had
nothing to do with, and credited the reader with one they did not build.

Not closed, in either direction. The sandbox is answering the rung it is asked
about, and a model that had to know every daemon's authentication policy would
be a model of a machine rather than of a ladder. Measured against tailcat
0.6.0.

### 7 · There is no `tailcat0`, and rung 4 is a stronger claim than the model makes

Open, and this one makes the model's own lesson better rather than worse.

The sandbox gives the tunnel an interface. `choosePath` returns
`iface: "tailcat0"`, the packet log shows addresses on it, and rung 4 is
skipped with the words *"nothing ever arrived on an interface UFW filters"* —
which implies there is an interface, and that UFW simply does not filter it.

There is no interface. Tailcat is userspace: no TUN device, no netlink, no
route, nothing for `ip link` to list and nothing a firewall rule could name
even in principle. Measured on `lab-ubuntu` with a tunnel up and carrying a
session:

```
interfaces whose name contains "tailcat":  0

ss -tnp | grep tailcat
ESTAB 0 0  10.0.13.2:37788  203.0.113.3:443  users:(("tailcat",pid=1149,fd=9))
```

One outbound socket, which is the whole of what a tunnel looks like from the
outside — and which is exactly the line the sandbox's own readout prints, so
the two agree about the evidence and disagree about the model behind it.

Left alone deliberately. `tailcat0` is a convenient fiction that makes the
sandbox's packet log readable, the log is honest about the address being
opaque, and correcting it would cost the drawing more than the accuracy is
worth. The lab records the stronger version: rung 4 is not skipped because UFW
declines to filter this interface. It is skipped because there is no interface,
and nothing arrived. Measured against tailcat 0.6.0.

### 8 · The command chapter 01 prints is not the command that runs

Open, and it is the smallest finding here with the sharpest edge, because it is
the one a reader will hit by typing.

[Chapter 01](../chapters/01-tailscale.html) and the sandbox both print:

```
tailcat serve ssh --ssh-authorized-keys=~/.ssh/authorized_keys
```

tailcat 0.6.0 refuses it. Flags come before the service name, and a flag after
one is read as a second service:

```
invalid port or service to serve: "--ssh-authorized-keys=…" is not a known
named service (want one of: all, ssh, no-auth-ssh, files, exit-node)
```

What runs is the same words in the other order, and it is what the lab's
**script** tab prints because it is what reached the machine:

```
tailcat serve --ssh-authorized-keys=/root/.ssh/authorized_keys ssh
```

Neither the chapter nor the sandbox is corrected here. Chapter 01 already ends
that section by telling you tailcat is young, that its flags may move, and to
check `tailcat serve --help` on your installed version rather than trusting the
lines above — which is the right advice and is exactly the advice this finding
is an instance of. Recording it is the point; a guide that silently tracked
every flag reordering would be teaching you to trust it instead. Measured
against tailcat 0.6.0.

---

## Folklore the lab settled

The sandbox and the lab agree about this one completely, and always have, so it
is not a disagreement. It is here because running the lab killed a belief that
almost everybody holds, including the person who built both of them.

It sits outside the list above on purpose. That list is for places where the
sandbox and the lab give different answers, and counting this one among them is
what made every summary of the list come out wrong: four disagreements and one
demonstration were being added up as though they were five of the same thing.

### A twenty-second blackout does not kill an SSH session

This one is folklore worth killing. Press **ssh and mosh, through a 20-second
outage** and read the first half of the result: both sessions survive the
blackout. TCP does not give up on a stalled connection anywhere near that fast,
so a tunnel, a lift or a dead spot is not what ends your session.

What ends it is the address changing underneath the connection, which is
what actually happens when a phone moves between networks. So the demonstration
has a second act: `lab-roam` gets a new address, and SSH stops dead while Mosh
carries on, because Mosh is not holding a connection to lose.

On **the board** those are two acts you watch rather than two halves of a
paragraph. The ssh tunnel snaps at the machine end and its traffic scatters,
still sealed, still going nowhere, while the mosh tunnel goes translucent,
holds, and re-solidifies against the new address. All four tick counts reach
the drawing as numbers, on `Result.Evidence`; the two addresses reach it on
`Result.Detail`, because a drawing that has to regex `Raw` to find out what
`lab-roam` moved to is one rewording away from lying.

A typical run:

```
eth0 down at 10:18:02
eth0 up   at 10:18:22
after the blackout:  ssh reached tick 45, mosh reached tick 45

roamed to 10.0.27.77
after the roam:      ssh reached tick 45, mosh reached tick 70
```

It runs against `lab-vps`'s **public** address on purpose. Over the tailnet both
sessions survive both acts, because the tailnet address does not change when the
network under it does, which is the tailnet earning its keep, and a good reason
to read chapters 01 and 03 together.

This one is TCP's behaviour and mosh's, not any coordination server's, so it is
the finding least likely to move under you. Measured against tailscale
1.102.3.

#### The sandbox has this now too, and here is exactly what it does instead

Until ticket #49 this demonstration existed only here, which made it the one
place the lab could show something the model could not express at all: the model
had a link that went up and down, loss, delay and a UDP port, and no session for
any of it to happen to. Chapter 14 now carries the same button, with the same
label, in the same place under the attack list, and a reader who can drive one
can drive the other blind.

What it does not carry is a measurement. The two halves are honest in different
ways here, and the split is worth knowing before you quote either:

- **The tick counts are computed there, read off two real sessions here.** The
  sandbox runs the same schedule this does — ten seconds to settle, twenty with
  no link, fifteen more, then the roam and twenty-five more — and turns it into
  the same tick counts by arithmetic, because a tick is a second of session time
  that survived the trip. The numbers agree with the run above. They agree
  because they were built to, not because anything was observed.
- **Twenty seconds is asserted there, waited here.** The lab's blackout costs
  twenty real seconds and the board's fourth rule is that time is not faked. The
  model's blackout costs nothing at all, and Linux's `tcp_retries2` is a
  constant in a comment rather than a threshold the run could cross. There is no
  lever to make the blackout longer, so the model cannot be made to disagree
  with its own explanation.
- **The failure this lab has and the model does not.** `demoOutage` has a branch
  for Mosh printing nothing, which is what a `ufw` command failing to open
  `60000:61000/udp` looks like from the outside, and it is chapter 03's
  commonest real failure. Both halves open the range for the duration and take
  it away again, so neither *ought* to reach it — but only one of them has a
  `ufw` that can refuse. The model names the trap in prose; it cannot walk you
  into it.

None of that is a disagreement, and it is deliberately not filed as one. The
two halves give the same answer to the same question, in the same order, with
the same words on the button, and the list above is for the places where they do
not. What the three points above are is the boundary of what the model was
asked — the same distinction chapter 14 makes in its own *real, modelled,
absent* table, which now names these tick counts under *modelled*.

The other button underneath the attack list, **Rotate the key**, still has no
sandbox equivalent. That is the asymmetry left over after that ticket, and it is
a real one: continuity through a re-key is a thing you can only watch happen to
something that is actually running.

---

## Headscale, not Tailscale

[Chapter 13](../chapters/13-lab.html) tells you to use a real throwaway tailnet
for the hand-built VM rig, and that advice still stands there. This stack
diverges on purpose.

Why: a lab you are going to point an attacker at should not need an account,
an internet connection, or anybody's production infrastructure. Headscale makes
this offline, free, repeatable and safe to break. `make reset` throws the whole
control plane away and the next `make up` is a lab that has never existed
before.

What it costs you: Headscale is a compatible reimplementation, so a
behaviour you observe here is *Headscale's* behaviour. Chapter 01 describes
Tailscale's. They agree on almost everything; do not assume they agree on
everything. Two places where they do not:

- Tailnet lock does not exist in Headscale. The **Tailnet lock** switch in
  this lab controls the nearest honest equivalent: whether a key exists at all
  for a machine you did not authorise. With it on, `evil-box` cannot join and
  gets no session, which is the property tailnet lock gives you, reached by a
  different mechanism. The lab says so in the result text rather than hiding it.
  What it does not do is end the story: a machine with no tailnet session is an
  ordinary machine on the internet, and what it reaches next is the host
  firewall's question. See finding 4 above.
- The tailnet's DERP lives inside the coordination server. A separate one
  would need its own trusted TLS certificate, and for the tailnet that buys
  nothing: the relay path a client takes is identical either way, and forcing
  traffic onto that path is what the lab actually tests.

  There is now a separate `derper` as well, and it is not a reversal of that.
  It exists for tailcat, which cannot use the embedded one and should not, and
  it costs the lab no new trust root because the CA it needed was already
  there. [The relay tailcat uses](#the-relay-tailcat-uses-and-why-it-is-not-the-other-one)
  has the reasoning.

### A Headscale wrinkle the control server used to work around

Headscale 0.26's policy manager kept its own snapshot of the nodes and did not
refresh it when `headscale nodes tag` changed one. A tag applied while it was
running was visible in `headscale nodes list` and invisible to every ACL:
every rule mentioning it silently compiled to nothing, and you got rung-3
denials with no explanation anywhere. The control server worked around it by
restarting the coordination server whenever it changed a tag.

0.29.3 does not need that, and the restart is gone. It was checked rather
than assumed: with the coordination server left running, retagging `lab-vps`
away from `tag:server` closes the `tag:laptop → tag:server:22` grant within
seconds and retagging it back opens it again, and the same holds for
`lab-ubuntu` on the source side of the same rule.

If it ever comes back it will look like a grant that stops working after a
configuration change and starts again after `docker restart headscale`.
`EnsureTags` in `control/state.go` is the place, and its comment carries this
paragraph in short form.

---

## The published-port trap, and what is real in it

Chapter 08's trap is reproduced with the exact chains dockerd writes:

```
iptables -I FORWARD 1 -j DOCKER-USER
iptables -I FORWARD 2 -j DOCKER
iptables -t nat -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
iptables -t nat -A DOCKER ! -i <lan> -p tcp --dport 8080 -j DNAT --to 10.0.11.20:80
```

`lab-vps-web` is a genuine second container on a bridge `lab-vps` routes for, so
the packet really is **forwarded** rather than delivered locally, which is the
whole reason `ufw`'s `INPUT` rules never get a say. `ufw status verbose` says
`Default: deny (incoming)` and `curl http://203.0.113.11:8080/` answers `HTTP
200` from `evil-box`, on the open segment, with no credentials.

What is not real: dockerd. Running a real Docker daemon inside `lab-vps`
would mean a privileged container, and a privileged container is a genuine
escape route onto your own machine. The mechanism under test is the chain order,
and the chain order is exact. `images/node/docker-trap.sh` says the same thing
in more detail, next to the rules.

Similarly, `evil-box` takes the on-path position by being handed
`lab-ubuntu`'s default route rather than by stealing it with ARP spoofing. What
that changes is how the attacker got there. What it does not change is one byte
of what follows: the frames are real, the capture is real, and the reason you
cannot read them is real.

---

## Commands

```bash
make up         # build and start, then wait for the three machines to join
make attack     # add evil-box — it never starts on its own
make status     # tailscale status and netcheck, from the laptop
make audit      # the eleven checks, scored, from the command line
make check      # Go and JavaScript — the one target that runs with the lab down
make ui         # just the JavaScript half: parse-check ui/, run the board rules
make hooks      # install the pre-push hook that runs make check for you
make logs       # follow every container
make shell M=lab-vps
make down       # stop everything, keep the state
make reset      # delete containers, networks and volumes — a clean lab
```

`make reset` is thorough on purpose: it removes the state volume holding the CA
and the pre-auth keys, the coordination server's database, and each machine's
tailscale identity. There is nothing to carry a broken experiment forward.

### Before you push

`make check` is the one target that wants Go rather than Docker, and the one
that works with the lab down:

```bash
make check      # go vet ./...  ·  go test ./...  ·  gofmt -l .  ·  the UI JavaScript
```

The first three run against `control/`, the only Go in the repo, and all three
finish in about a second, which is the point, because a check you have to
bring the lab up for is a check you will skip. `gofmt` fails on any output at
all: a file listed is a file that is not formatted.

It is worth the second because of the four board rules: nothing drawn that
was not measured, a failed attack is not a green tick, `danger` outranks `ok`,
time is not faked. Those are the kind of invariant that erodes without anyone
deciding to erode it, and four test files guard them:

| File | What it holds |
|---|---|
| `attacks_test.go` | the parsers, the evidence round-trips the board draws from, and the tunnel's four endings |
| `probe_test.go` | the five-rung ladder, against `tailscale ping`, `nc` and `tcpdump` output captured from a running lab |
| `audit_test.go` | the eleven checks, the score, and the five numbers in the comparison table above |
| `state_test.go` | what `ufw`, `sshd -T` and `headscale` say about the machine, which decides three of the eleven |

None of them start a container. The rung is a pure function of what one command
printed at one end and another printed at the other, and the score is a pure
function of eleven booleans, so the fixtures were captured once, checked in,
and the decisions they drive are now asserted in about a second rather than in
about a minute. That matters more than a coverage number: finding 4 above was
a rung-classification bug in exactly that pure function, it survived for
months, and it was caught by running containers.

### The JavaScript half

`control/ui/` is about three thousand lines, and it ships exactly as written:
`//go:embed ui` puts it in the binary, `app.js` is a classic script, `hud/` is
ES modules served over HTTP, and nothing anywhere compiles, bundles or
minifies. That is deliberate, and it is why `docker compose up` is the only
prerequisite, but it means a stray comma reaches the browser intact.

The browser is then quiet about it in the worst possible way. `run()` in
`hud/setpieces.js` wraps every shot in a `try`/`catch` so a broken set-piece
cannot take the page down: it logs, clears, and `app.js` falls back to the text
trace. That is the right behaviour and it stays. It also means that, to anyone
driving the lab, a typo in a set-piece looks almost exactly like an action that
never had a set-piece, which is how `rotate-key` went a release with nothing
drawn and nothing said about it.

So `make check` ends with two cheap answers to that, in `checks/`:

| File | What it holds |
|---|---|
| `syntax.mjs` | `node --check` over the eight files the browser loads, each in the goal it is loaded in: script for `app.js` and the guide's `assets/`, module for `hud/` |
| `reading.test.mjs` | the board rules themselves: `danger` outranks `ok`, a scan that never ran reports no counts, an empty capture draws an empty tray, two rungs are skipped rather than passed |
| `setpieces.test.mjs` | that `hud/` still links, and that `missing()` names an action with no shot; the check ticket 33 did not have |

That second one is the point of the exercise. The four honesty rules at the top
of `setpieces.js` were guarded on the Go side only, which guards what the
server *reports* and not what the board *does with it*, and the shots are
precisely where `run()` hides a mistake. So the deciding half moved into
`hud/reading.js`: pure functions of a `Result`, no three.js, no canvas, no DOM,
which is what lets twenty assertions run in under a tenth of a second.
`setpieces.js` imports them, so the tests hold the code the board actually runs
rather than a copy of it.

`setpieces.test.mjs` then imports `hud/setpieces.js` for real, three.js and
all, to catch the one break a parse check cannot: a file that parses perfectly
and still fails when the browser links it, because an import names something
the other module does not export. On the page that is a module that never
evaluates and a board that never appears. That test tells a link failure from
three.js wanting a browser Node cannot give it, and only skips for the second.

```bash
make ui         # or: node checks/syntax.mjs && node --test checks/*.test.mjs
```

Node is not a prerequisite, and is not becoming one. There is no `npm`
here, no `package.json`, no `node_modules`, and nothing in `checks/` uses
anything Node does not ship with. If Node is missing, or older than 18, which
is what `node --test` wants, `make check` prints a line saying so and holds.
Failing the gate over a tool the lab does not require would only teach people
to reach for `--no-verify`, and Docker remains the one thing you have to have.

`hud/three.module.js` is not parse-checked: it is vendored, minified three.js,
where a parse error means a bad copy rather than a typo.

If you would rather not remember:

```bash
make hooks
```

That copies `hooks/pre-push` into `.git/hooks/pre-push`, and from then on
`git push` runs `make check` first and stops if it fails. It is opt-in because
a hook installed behind your back is a worse papercut than the one it
prevents, and it is `pre-push` rather than `pre-commit` for a related reason:
the checks are fast but not free, and a commit is not where this matters.

Push past it once, or be rid of it entirely:

```bash
git push --no-verify
rm .git/hooks/pre-push
```

`make hooks` will not overwrite a `pre-push` hook it did not write. If you
already have one it says so and leaves it where it is.

There is no CI here, and that is a decision rather than an omission. This lab
runs on your machine with Docker and nothing else, and a check that only runs
on somebody else's hardware, after the fact, does not fit that.

## Where things are

```
lab/
├── docker-compose.yml     the whole topology, and the only file you edit to change it
├── Makefile               up / attack / audit / check / reset
├── hooks/pre-push         what `make hooks` installs: make check before a push
├── checks/                the JavaScript half of `make check` — no npm, no packages
│   ├── syntax.mjs         node --check over every file the browser loads
│   ├── reading.test.mjs   the board rules, asserted without a browser
│   └── setpieces.test.mjs that hud/ links, and that no action lost its shot
├── config/headscale/      coordination server configuration, commented
├── images/
│   ├── node/              a lab machine: tailscaled, tailcat, sshd, ufw, mosh
│   │   ├── entrypoint.sh  six steps, in chapter 08's order
│   │   └── docker-trap.sh the published-port trap, and what is real in it
│   ├── nat/               one home router per segment
│   ├── derp/              tailcat's relay: derper, pinned, holding nothing
│   └── evil/              the attacker, and the on-path switch
└── control/
    ├── main.go            routing, the embedded UI, the loopback guard, the CA
    ├── docker.go          the only file that talks to Docker
    ├── state.go           the machines, the configurations, observation
    ├── actions.go         one function per switch, and the five-rung probe
    ├── attacks.go         one function per attack
    ├── audit.go           the eleven checks
    ├── stream.go          server-sent events: status, tcpdump, logs, stats
    ├── panels.go          the panel spec the UI renders
    ├── *_test.go          fixtures captured from a live lab; no containers needed
    └── ui/                the same vocabulary as chapter 14
        ├── index.html     the shell: both drawings, the two tab strips, the guide
        ├── app.js         a classic script, the same shape as assets/sandbox.js
        └── hud/
            ├── three.module.js  three.js r166, MIT, inside the binary
            ├── scene.js         the board: five gates, three planes, the packet
            ├── reading.js       what a Result says — pure, and the only tested part
            └── setpieces.js     one exported function per attack id
```

### If you edit the UI, rebuild

`main.go` does `//go:embed ui`, so the page you get on :8099 is the copy
compiled into the binary, not the one on disk. Editing anything under
`control/ui/` does nothing at all until you rebuild:

```bash
docker compose up -d --build control
```

That is the whole loop for a UI change, and it takes a few seconds because
everything else is cached. It costs less than the ten minutes of confusion it
saves, which is roughly how long it takes to work this out by staring at a
change that will not appear.

The trade is deliberate: the alternative is a bind mount, and then the lab
depends on where you cloned it and the binary stops being the one artefact
that carries everything.

## If something will not start

- `/dev/net/tun` is missing. The machines need it to run real WireGuard.
  Docker Desktop provides it; a hardened host may not. Tailcat does not need
  it — it is userspace, which is half of why chapter 01 calls it the hatch you
  can use on a box where you have neither root nor a daemon.
- A tunnel will not start, and says no address was printed. It needs the lab's
  relay: `docker compose logs derp`. The usual cause is a state volume from
  before the relay existed — the control server replaces the CA and says so in
  its log, and `make reset && make up` is the clean way through.
- A machine never joins. Try `docker compose logs lab-ubuntu`. The usual cause
  is that the lab CA was not there when it booted; `make reset && make up`.
- Every attack refuses at rung 1 with `nat-evil is stopped` or
  `nat-evil is not in this stack`. That is the refusal working: the attacker
  cannot reach anything, so nothing it does can be scored. `docker start
  nat-evil`, or `make attack` if it was never created — starting `evil-box`
  on its own with `--no-deps` leaves exactly this.
- Every probe dies at rung 3. Check `docker exec headscale headscale policy get`,
  then `docker exec headscale headscale nodes list` and confirm each machine
  carries the tag the policy names. See the Headscale wrinkle above.
- The control server refuses to start. Read what it says. It is almost
  certainly the loopback guard, and it is almost certainly right.
- A change to the page does not appear. The UI is compiled into the
  binary. `docker compose up -d --build control`. See
  [If you edit the UI, rebuild](#if-you-edit-the-ui-rebuild).
