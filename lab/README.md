# The lab

A disposable network you can break. Real containers, real kernels, real
WireGuard, real packets — and a control surface where every button is a command
that actually runs.

```bash
cd lab && docker compose up -d
open http://localhost:8099
```

Docker is the only prerequisite. No Go, no Python, no npm, no account, no
internet connection after the images are built.

This is the **feel-it** half of a pair. The **understand-it** half is
[chapter 14's sandbox](../chapters/14-sandbox.html), which runs the same
topology as a model in your browser. Same panel names, same button labels, same
output format: if you can drive one you can drive the other blind. The
difference is that the sandbox can only show you what somebody modelled, and
this one has no model — so it can surprise you. It has already surprised us
twice, and both surprises are written down further below.

---

## Safety, before anything else

**`evil-box` attacks containers you started, on hardware you own, on bridges
that go nowhere.** It is behind a compose profile and does not exist until you
ask for it with `--profile attack`. Its network reaches the other lab
containers and nothing else — not your LAN, not your router, not the machine
you are reading this on.

The control server holds `/var/run/docker.sock`, which means anything that can
talk to it can run commands as root on your machine. It therefore:

- has **no authentication**, because nothing off this host can reach it;
- is published to `127.0.0.1:8099` only;
- **reads its own port bindings at startup and refuses to run** if it finds
  itself published anywhere else.

Do not change that `ports:` line. If you do, the server will tell you why it is
not starting.

Everything here is provided **as is**, with no warranty of any kind, under the
[MIT licence](../LICENSE). The full terms and the reasoning behind them are in
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
| `headscale` | Coordination server **and** the lab's DERP relay | one process, two roles — see the Headscale section |
| `lab-vps` | The public box — [chapter 08](../chapters/08-vps.html) | `tailscaled`, `sshd`, `ufw`, and the published-port trap |
| `lab-vps-web` | The container behind the published port | reachable only through `lab-vps`, and only when you turn the trap on |
| `lab-ubuntu` | The laptop — [chapter 09](../chapters/09-ubuntu.html) | `tailscaled`, `sshd`, `mosh` |
| `lab-roam` | The roaming client — [chapters 03](../chapters/03-mosh-blink.html) / [04](../chapters/04-tmux-herdr.html) | behind a deliberately unfriendly NAT |
| `nat-ubuntu`, `nat-roam`, `nat-evil` | One home router per machine | masquerade only, no port forwards |
| `evil-box` | The attacker | `nmap`, `tcpdump`, `tcpreplay`, `hping3`, `dsniff`, `wireguard-tools`. **Opt in with `--profile attack`** |

### The shape of the network

```
lan-ubuntu 10.0.13.0/24 --[ nat-ubuntu 203.0.113.13 ]--\
lan-roam   10.0.27.0/24 --[ nat-roam   203.0.113.27 ]---+-- wan 203.0.113.0/24
lan-evil   10.0.66.0/24 --[ nat-evil   203.0.113.66 ]--/      |
                                                              |- headscale 203.0.113.2
                                                              |- lab-vps   203.0.113.11
```

Every machine sits on its own segment behind its own router. That is the point
and it is not decoration: if they all shared one bridge, "NAT traversal" would
be a word rather than a thing that has to happen, and
[chapter 01](../chapters/01-tailscale.html) would be untestable here. The
addresses on the shared segment are RFC 5737 documentation addresses, so
nothing in this lab can be mistaken for a real host.

`nat-roam` runs with `MASQUERADE --random`, which allocates a fresh source port
per destination. That is an endpoint-*dependent* mapping — the unfriendly kind,
the kind a phone on mobile data often gets — and it is why `lab-roam` is the
machine that falls back to the relay first when anything else goes wrong.

---

## Driving it

Everything below is one click in the UI. The command shown is what actually
runs, and the **script** tab collects them all in order so you can paste them at
the three Lima VMs in [chapter 13](../chapters/13-lab.html).

### The picture

The same drawing as chapter 14, at the top of the page, with the model taken
out of it. Every address on it was read back from a container, and the shape of
the line is whatever `tailscale ping` last reported:

- **straight across the middle** — direct, the punch completed;
- **bending up through the box in the centre** — relayed through DERP;
- **dipping into the red band** — it crossed the public segment, and the band
  lights up to say so.

Before you probe anything it says **idle · run a probe**, and it means it. An
idle Tailscale peer reports no current address, which looks exactly like a relay
if you take it at face value; saying "relay" about a pair that has simply not
spoken yet would be the most misleading thing this page could do. So it waits
until there is something true to draw.

### Panels

Four, with the same names and the same switches as the sandbox page:

- **Machines** — who is running, who the tailnet will accept, and whether
  `evil-box` is sitting on `lab-ubuntu`'s segment.
- **The network** — the three levers chapter 13 shapes by hand: `ip link`,
  `tc netem` loss and delay, and an `nft` rule dropping WireGuard's UDP port.
- **Tailnet policy** — the default action, four named grants, tailnet lock,
  key expiry, Tailscale SSH.
- **The host — lab-vps** — `ufw` defaults and rules, the published container
  port, `sshd`'s `ListenAddress`, `PasswordAuthentication`, `PermitRootLogin`.

### Probe

The probe never answers yes or no. It answers **which rung**, using the same
five-rung ladder [chapter 12](../chapters/12-troubleshooting.html) teaches — and
unlike the sandbox, it works the rung out from evidence rather than from a
model:

1. Is anything alive? Containers, links, tailnet sessions.
2. Is there a path, and is it direct or relayed? Answered by `tailscale ping`,
   which keeps trying until it gets a direct path or runs out of attempts, so
   what you see is the path the pair settles on.
3. Did the tailnet allow it? The probe starts a `tcpdump` on the destination
   before it knocks. **If nothing arrives, the tailnet refused it** — and the
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

Nine buttons, the same nine as the sandbox, and each one ends by naming the
defence that answered it.

| Attack | What it actually does | What it proves |
|---|---|---|
| Scan from the open internet | `nmap` from `evil-box` at `lab-vps`'s public address | what a stranger sees with no credentials |
| Scan from inside the tailnet | joins `evil-box`, then probes all three machines | membership is not authorisation — unless you left it that way |
| Sit on the wire and capture | puts `evil-box` on `lab-ubuntu`'s route and runs `tcpdump` | see below: this one has a control experiment in it |
| Replay a captured frame | `tcpreplay` of the captured WireGuard frames, 20 loops | the receiving kernel discards every one |
| Join with a stolen node key | `tailscale up` on `evil-box` with a key it should not have | what a leaked key is worth, with and without something vouching for it |
| Let a key expire | `headscale nodes expire` on `lab-roam` | the lost phone that removes itself |
| Advertise a rogue exit node | `tailscale set --advertise-exit-node` on `evil-box` | an exit node is a route *offer*; approval is separate from membership |
| Publish a Docker port | writes the chains dockerd writes, then curls from outside | UFW says deny; the port answers anyway |
| Run the build order wrong | deletes both the public and the tailnet `ufw` rules | the lock-out, on a machine you can afford to lose |

Two more buttons sit underneath: **ssh and mosh, through a 20-second outage**
and **Rotate the key**.

#### The capture has a control experiment in it

"We captured the traffic and could not read it" proves very little on its own —
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

---

## Named configurations

The same four ids as the sandbox, with the same meanings, as compose profiles:

```bash
docker compose --profile day-one  up cfg-day-one    # or: make day-one
docker compose --profile typical  up cfg-typical
docker compose --profile weak     up cfg-weak
docker compose --profile hardened up cfg-hardened
```

Each one runs the same code the button in the UI runs — one binary, one code
path, so the two cannot drift apart.

Then score it:

```bash
make audit          # or press "Audit this configuration"
```

Eleven checks, the same eleven as the sandbox, with the same labels and the same
rubric. The only thing that changed is how each one is answered: there it asks a
model, here it asks a container. **Two of the eleven ask whether *you* can still
get in.** They are not padding — without them, a machine you have locked
yourself out of scores nearly perfectly and "closed" reads as "secure".

The audit takes about a minute, because five of the eleven really do join and
unjoin the attacker. It needs `evil-box`; without it the lab refuses to produce
a score rather than reporting one with five holes in it.

One check is marked **cannot pass here** rather than failed, and the verdict says
so: it still counts against the score, because a number that flatters itself is
worth nothing, but you should not spend an evening hunting for a switch that does
not exist. `hardened` therefore reads *"10 of 11 held, and the one that did not
cannot pass in this lab at all"* — see the next section for why.

---

## Where this lab and the sandbox disagree

This is the most valuable part of the directory. A gap between the model and the
containers means the model is wrong about something real, and finding those was
the whole reason for building both halves.

Both columns below were measured, not derived — the sandbox scores come from its
own comparison table, the lab scores from `make audit` against each profile:

| Configuration | Sandbox | This lab | Why they differ |
|---|---|---|---|
| `day-one` | 3/11 | **4/11** | the laptop is behind a NAT (below) |
| `typical` | 4/11 | 4/11 | — |
| `weak` | 2/11 | 2/11 | — |
| `hardened` | 11/11 | **10/11** | key expiry (below) |
| the boot state | 9/11 | **8/11** | key expiry (below) |

Two divergences account for every one of those gaps, and in both the containers
are right and the model is not quite. A third and a fourth show up when you
drive it rather than score it. All four are below.

### 1 · The hardened configuration scores 10/11 here and 11/11 in the sandbox

The check that fails is **"A lost device stops being a member on its own"**.

Headscale records a node expiry only when the registration asks for one, and a
registration made with a pre-auth key does not — so `headscale nodes list` shows
`Expiration: N/A` for all three machines and the check reads that honestly. It
is a real difference between Headscale and Tailscale, not a misconfiguration
you can fix from the UI, and the lab will not pretend otherwise. For the same
reason, turning **Key expiry** *off* returns a typed refusal explaining that
Headscale has no such switch, instead of quietly doing nothing.

What still works, and is worth doing: **Let a key expire** calls
`headscale nodes expire` and you can watch `lab-roam` fall out of the tailnet on
its own within seconds. The mechanism is real; only the standing configuration
is missing.

### 2 · Nobody can reach your laptop from the internet, and the sandbox thinks they can

`day-one` scores 4/11 here and 3/11 in the sandbox. The extra pass is
**"…nor your laptop"**, checked with the tailnet switched off entirely.

The sandbox gives every machine a public address and lets a public path find
one, so an attacker on the open internet reaches `lab-ubuntu:22`. In the
containers it does not, and cannot: `lab-ubuntu` lives on `10.0.13.0/24` behind
`nat-ubuntu`, which masquerades outbound and forwards nothing inbound. There is
no address for a stranger to aim at. The probe says so at rung 2 rather than
inventing a path.

That is what a laptop behind a home router actually looks like, and it is worth
knowing which of the two you have been picturing. It also does not let the
configuration off the hook: the moment the laptop joins a tailnet, it becomes
reachable from every other member, and checks 6 and 7 are what watch that.

### 3 · Blocking UDP does not make `netcheck` say `UDP: false`

The sandbox shows `tailscale netcheck` reporting `UDP: false` when you drop
WireGuard's port. The real thing does not, and it is right not to:
`nft ... udp dport 41641 drop` blocks WireGuard, while `netcheck` probes UDP
reachability using STUN on port 3478, which is still open. What *does* change,
within a few seconds, is the path — `direct` becomes `relay`, exactly as the
chapter says.

A network that really does block all outbound UDP would report `UDP: false`.
This lab blocks the port [chapter 13](../chapters/13-lab.html) tells you to
block, because the generated script has to be the script that chapter runs.

### 4 · A twenty-second blackout does not kill an SSH session

This one is folklore worth killing. Press **ssh and mosh, through a 20-second
outage** and read the first half of the result: both sessions survive the
blackout. TCP does not give up on a stalled connection anywhere near that fast,
so a tunnel, a lift or a dead spot is not what ends your session.

What ends it is the **address changing underneath the connection**, which is
what actually happens when a phone moves between networks. So the demonstration
has a second act: `lab-roam` gets a new address, and SSH stops dead while Mosh
carries on, because Mosh is not holding a connection to lose.

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
network under it does — which is the tailnet earning its keep, and a good reason
to read chapters 01 and 03 together.

---

## Headscale, not Tailscale

[Chapter 13](../chapters/13-lab.html) tells you to use a real throwaway tailnet
for the hand-built VM rig, and that advice still stands there. This stack
diverges on purpose.

**Why:** a lab you are going to point an attacker at should not need an account,
an internet connection, or anybody's production infrastructure. Headscale makes
this offline, free, repeatable and safe to break. `make reset` throws the whole
control plane away and the next `make up` is a lab that has never existed
before.

**What it costs you:** Headscale is a compatible reimplementation, so a
behaviour you observe here is *Headscale's* behaviour. Chapter 01 describes
Tailscale's. They agree on almost everything; do not assume they agree on
everything. Two places where they do not:

- **Tailnet lock does not exist in Headscale.** The **Tailnet lock** switch in
  this lab controls the nearest honest equivalent: whether a key exists at all
  for a machine you did not authorise. With it on, `evil-box` cannot join,
  gets no session, and is refused at rung 1 before any policy is consulted —
  which is the property tailnet lock gives you, reached by a different
  mechanism. The lab says so in the result text rather than hiding it.
- **DERP lives inside the coordination server.** The ticket this was built from
  asked for a separate `derper` container. A separate one needs its own trusted
  TLS certificate, which means shipping a CA for no gain: the relay path a
  client takes is identical either way, and forcing traffic onto that path is
  what the lab actually tests.

### A Headscale wrinkle the control server works around

Headscale 0.26's policy manager keeps its own snapshot of the nodes and does not
refresh it when `headscale nodes tag` changes one. A tag applied while it is
running is visible in `headscale nodes list` and **invisible to every ACL** —
every rule mentioning that tag silently compiles to nothing, and you get
rung-3 denials with no explanation anywhere.

The control server therefore restarts the coordination server whenever it
changes a tag. The nodes reconnect on their own within a few seconds. If a later
Headscale drops this behaviour, drop the restart with it —
`EnsureTags` in `control/state.go` is the place.

---

## The published-port trap, and what is real in it

Chapter 08's trap is reproduced with the exact chains dockerd writes:

```
iptables -I FORWARD 1 -j DOCKER-USER
iptables -I FORWARD 2 -j DOCKER
iptables -t nat -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
iptables -t nat -A DOCKER ! -i <lan> -p tcp --dport 8080 -j DNAT --to 172.31.8.20:80
```

`lab-vps-web` is a genuine second container on a bridge `lab-vps` routes for, so
the packet really is **forwarded** rather than delivered locally — which is the
whole reason `ufw`'s `INPUT` rules never get a say. `ufw status verbose` says
`Default: deny (incoming)` and `curl http://203.0.113.11:8080/` answers `HTTP
200` from `evil-box`, on the open segment, with no credentials.

**What is not real:** dockerd. Running a real Docker daemon inside `lab-vps`
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
make logs       # follow every container
make shell M=lab-vps
make down       # stop everything, keep the state
make reset      # delete containers, networks and volumes — a clean lab
```

`make reset` is thorough on purpose: it removes the state volume holding the CA
and the pre-auth keys, the coordination server's database, and each machine's
tailscale identity. There is nothing to carry a broken experiment forward.

## Where things are

```
lab/
├── docker-compose.yml     the whole topology, and the only file you edit to change it
├── Makefile               up / attack / audit / reset
├── config/headscale/      coordination server configuration, commented
├── images/
│   ├── node/              a lab machine: tailscaled, sshd, ufw, mosh, tmux
│   │   ├── entrypoint.sh  six steps, in chapter 08's order
│   │   └── docker-trap.sh the published-port trap, and what is real in it
│   ├── nat/               one home router per segment
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
    └── ui/                the same vocabulary as chapter 14
```

## If something will not start

- **`/dev/net/tun` is missing** — the machines need it to run real WireGuard.
  Docker Desktop provides it; a hardened host may not.
- **A machine never joins** — `docker compose logs lab-ubuntu`. The usual cause
  is that the lab CA was not there when it booted; `make reset && make up`.
- **Every probe dies at rung 3** — check `docker exec headscale headscale policy get`,
  and see the Headscale wrinkle above.
- **The control server refuses to start** — read what it says. It is almost
  certainly the loopback guard, and it is almost certainly right.
