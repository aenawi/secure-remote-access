# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Hashem Aldhaheri

# The lab, in ten words or fewer per target.
#
#   make up       bring the lab up and tell you where to look
#   make attack   add evil-box — nothing hostile exists until you do
#   make audit    the eleven checks, from the command line
#   make check    Go and JavaScript both — no containers, no network, a second
#   make reset    throw everything away and start clean
#
# Docker is the only thing you need installed to run the lab. `make check`
# is the exception, and wants Go instead: it is the one target that works
# with the lab down. It will also use Node if you have it, for the UI
# JavaScript, and say so and carry on if you do not.

COMPOSE ?= docker compose
URL     ?= http://localhost:8099

.DEFAULT_GOAL := help
.PHONY: help up attack down reset logs shell status audit check ui hooks \
        day-one typical weak hardened

help:
	@printf 'The lab — real containers, real WireGuard, real packets.\n\n'
	@printf '  make up         build and start the lab, then open %s\n' '$(URL)'
	@printf '  make attack     add evil-box (never starts on its own)\n'
	@printf '  make status     tailscale status from the laptop\n'
	@printf '  make audit      run the eleven checks and print the score\n'
	@printf '  make check      licences, links, go vet, go test, gofmt, and the UI JavaScript\n'
	@printf '  make ui         parse-check ui/ and assets/, run the board rules\n'
	@printf '  make hooks      install the pre-push hook that runs make check\n'
	@printf '  make logs       follow every container\n'
	@printf '  make shell M=lab-vps   a root shell on one machine\n'
	@printf '  make down       stop everything, keep the state\n'
	@printf '  make reset      stop everything and delete containers, networks and volumes\n\n'
	@printf 'Configurations (same four ids as the sandbox on chapter 14):\n'
	@printf '  make day-one | make typical | make weak | make hardened\n\n'

up:
	$(COMPOSE) up -d --build
	@printf '\nWaiting for the three machines to join the tailnet…\n'
# The three machines by name, not a count of registrations. Counting is wrong
# twice over: `"id"`, which this used to grep for, appears four times per node
# on 0.29 — its own, its user's, and two on the pre-auth key — so the loop
# stopped the moment the first machine appeared; and any count at all is
# satisfied by `evil-box`, whose registration survives a `make down` in the
# hsdata volume, so a lab that came up with two of three would look ready.
# Registration is also not a working session, so the client is asked too.
	@for i in $$(seq 1 90); do \
	  ns=$$(docker exec headscale headscale nodes list -o json 2>/dev/null || true); \
	  ok=1; \
	  for m in lab-vps lab-ubuntu lab-roam; do \
	    printf '%s' "$$ns" | grep -q "\"given_name\": \"$$m\"" || ok=0; \
	  done; \
	  if [ "$$ok" = 1 ] && \
	     $(COMPOSE) exec -T lab-ubuntu tailscale status >/dev/null 2>&1; then break; fi; \
	  sleep 2; \
	done
	@$(COMPOSE) exec -T lab-ubuntu tailscale status 2>/dev/null || \
	  printf 'Not up yet. Try: make logs\n'
	@printf '\nOpen %s\n' '$(URL)'

attack:
	$(COMPOSE) --profile attack up -d --build
	@printf '\nevil-box is running. It has attacked nothing yet.\n'

down:
	$(COMPOSE) --profile attack down

# Everything: containers, networks, the state volume with the CA and the keys,
# and the coordination server's database. The next `make up` is a fresh lab.
reset:
	$(COMPOSE) --profile attack --profile day-one --profile typical \
	           --profile weak --profile hardened down -v --remove-orphans
	@printf 'Clean. `make up` starts again from nothing.\n'

logs:
	$(COMPOSE) logs -f

status:
	@$(COMPOSE) exec -T lab-ubuntu tailscale status
	@printf '\n'
	@$(COMPOSE) exec -T lab-ubuntu tailscale netcheck

M ?= lab-vps
shell:
	$(COMPOSE) exec $(M) bash

audit:
	@curl -fsS $(URL)/api/audit | \
	  python3 -c 'import json,sys; r=json.load(sys.stdin); \
print("%s / %s checks held" % (r.get("passed",0), r.get("total",0))); \
print(r.get("verdict","")); print(); \
[print(("  PASS  " if c["pass"] else "  FAIL  ") + c["label"]) for c in r.get("checks",[])]' \
	  2>/dev/null || curl -fsS $(URL)/api/audit

# The only target that needs no Docker and no lab. The three Go checks run
# against control/, the only Go in the repo, and finish in about a second —
# which is the point: this has to be runnable on a laptop with the lab down.
# `ui` is fourth and adds about a tenth of one, when Node is there.
check:
	@printf 'licences\n'
	@sh checks/licensed.sh
	@printf 'links\n'
	@sh checks/anchors.sh
	@printf 'go vet\n'
	@cd control && go vet ./...
	@printf 'go test\n'
	@cd control && go test ./...
	@printf 'gofmt\n'
	@cd control && unformatted=$$(gofmt -l .); \
	  if [ -n "$$unformatted" ]; then \
	    printf '\nNot gofmt-clean:\n'; \
	    printf '  %s\n' $$unformatted; \
	    printf '\nFix with: gofmt -w lab/control\n'; \
	    exit 1; \
	  fi
	@$(MAKE) --no-print-directory ui
	@printf '\nEverything held.\n'

# The UI is three thousand lines of JavaScript that ships exactly as written:
# `//go:embed ui` puts it in the binary, nothing compiles or bundles it, and a
# typo in a set-piece fails quietly on purpose — run() catches it so a broken
# shot cannot take the page down, which is right, and which also makes it look
# like an action that simply has no set-piece. So: a parse check over the files
# the browser loads, and the board's own rules asserted as pure functions.
#
# Node is not a prerequisite of this lab and is not becoming one. There is no
# npm here, no package.json and no node_modules — checks/ is two files that use
# nothing but what Node ships with. Without Node this prints a note and holds,
# because failing the gate for a tool the lab does not require would only teach
# people to pass --no-verify.
NODE_MIN := 18
ui:
	@printf 'ui js\n'
	@if ! command -v node >/dev/null 2>&1; then \
	  printf '  skipped — no node, and the lab does not ask for one.\n'; \
	  printf '  Node $(NODE_MIN)+ parse-checks ui/ and assets/ and runs the board rules.\n'; \
	  exit 0; \
	fi; \
	major=$$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0); \
	if [ "$$major" -lt $(NODE_MIN) ]; then \
	  printf '  skipped — node %s is older than $(NODE_MIN), which node --test needs.\n' "$$major"; \
	  exit 0; \
	fi; \
	node checks/syntax.mjs && node --test checks/*.test.mjs

# Opt-in on purpose: nothing installs this for you, and README.md says how to
# take it out again. A hook put there behind your back is a worse papercut
# than the one it prevents.
hooks:
	@configured=$$(git config --get core.hooksPath); \
	if [ -n "$$configured" ]; then \
	  printf 'core.hooksPath is set to %s, so git looks for hooks there.\n' "$$configured"; \
	  printf 'Copy hooks/pre-push into it yourself — guessing would install one git never runs.\n'; \
	  exit 1; \
	fi; \
	dir=$$(git rev-parse --git-path hooks) || exit 1; \
	mkdir -p "$$dir"; \
	dest=$$(cd "$$dir" && pwd)/pre-push; \
	if [ -e "$$dest" ] && ! grep -q 'lab/hooks/pre-push' "$$dest"; then \
	  printf 'There is already a pre-push hook at %s, and it is not this one.\n' "$$dest"; \
	  printf 'Left alone. Merge it by hand, or delete it and run make hooks again.\n'; \
	  exit 1; \
	fi; \
	cp hooks/pre-push "$$dest" && chmod +x "$$dest" && \
	printf 'Installed %s. It runs make check before every push.\n' "$$dest" && \
	printf 'Remove it with: rm %s\n' "$$dest"

day-one typical weak hardened:
	$(COMPOSE) --profile $@ up --build cfg-$@
	@printf '\nConfiguration "%s" applied. Audit it with: make audit\n' '$@'
