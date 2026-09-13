/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   Which rung decided it.

   The ladder under the board marks the rung that decided the last
   connection. This counts all of them, which answers a different question: a
   session where every denial came from rung 4 has tested the firewall a lot
   and the tailnet's access rules not at all, and that is invisible one
   verdict at a time.

   Allowed and denied are counted apart on purpose. "Rung 3 answered eleven
   times" is not a finding; "rung 3 allowed eleven and denied none" is, and
   so is the reverse. A bar that merged them would be the kind of drawing
   this project exists to argue against — a count with the outcome averaged
   out of it.

   Nothing here is drawn that was not measured. A rung with no verdicts
   against it shows a zero and no bar, rather than an empty bar that reads as
   a measurement of nothing happening.

   Options: none.
   ============================================================ */

const RUNGS = [
  [1, "is anything alive"],
  [2, "is there a path"],
  [3, "did the tailnet allow it"],
  [4, "did the firewall allow it"],
  [5, "was anything listening"]
];

export function create(host) {
  const el = host.el;
  const feed = host.feed;

  const counts = {};
  for (const [n] of RUNGS) counts[n] = { ok: 0, no: 0 };

  const rows = {};
  const table = document.createElement("div");
  table.className = "tally-rows";

  for (const [n, what] of RUNGS) {
    const row = document.createElement("div");
    row.className = "tally-row";

    const name = document.createElement("div");
    name.className = "tally-n";
    name.textContent = "RUNG " + n;
    name.title = what;

    const bar = document.createElement("div");
    bar.className = "tally-bar";
    const ok = document.createElement("span");
    ok.className = "tally-ok";
    const no = document.createElement("span");
    no.className = "tally-no";
    bar.appendChild(ok);
    bar.appendChild(no);

    const num = document.createElement("div");
    num.className = "tally-v";
    num.textContent = "0";

    row.appendChild(name);
    row.appendChild(bar);
    row.appendChild(num);
    table.appendChild(row);

    rows[n] = { ok: ok, no: no, num: num };
  }

  const foot = document.createElement("div");
  foot.className = "tally-foot";
  foot.textContent = "nothing has been run yet";

  el.appendChild(table);
  el.appendChild(foot);

  if (!feed) {
    foot.textContent = "no feed on this page";
    return {};
  }

  function record(data) {
    const res = data && data.result;
    if (!res || !counts[res.rung]) return;

    counts[res.rung][res.ok ? "ok" : "no"]++;
    draw();

    foot.textContent = (data.id || data.kind || "something") + " — " +
      (res.ok ? "allowed" : "denied") + " at rung " + res.rung;
  }

  function draw() {
    /* Every bar is a share of the busiest rung, not of the total. Shares of
       the total make four rungs invisible the moment one of them is being
       exercised, which is exactly when the other four matter. */
    let most = 0;
    for (const [n] of RUNGS) most = Math.max(most, counts[n].ok + counts[n].no);

    for (const [n] of RUNGS) {
      const c = counts[n];
      const total = c.ok + c.no;
      rows[n].ok.style.width = most ? (100 * c.ok / most) + "%" : "0";
      rows[n].no.style.width = most ? (100 * c.no / most) + "%" : "0";
      rows[n].num.textContent = total ? c.ok + " / " + c.no : "0";
      rows[n].num.title = total ? c.ok + " allowed, " + c.no + " denied" : "nothing reached this rung";
    }
  }

  const offVerdict = feed.on("verdict", record);
  const offFlow = feed.on("flow", record);

  return {
    destroy: function () {
      offVerdict();
      offFlow();
    }
  };
}
