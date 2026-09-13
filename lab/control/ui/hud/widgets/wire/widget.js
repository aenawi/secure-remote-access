/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   The wire.

   Every other widget reads the lab through the feed. This one reads the
   feed, which is the reading nothing else on the page does and the one that
   says whether to trust the rest.

   The number that matters is `dropped`. The server keeps a bounded queue per
   reader and throws frames away rather than blocking the lab on a slow tab,
   so a count above zero means there is a hole in what you are watching — and
   a drawing that interpolates across a hole is a drawing that is making
   things up. It is on a card because a recording made through a gap is worth
   knowing about before it is posted, not after.

   Options: none.
   ============================================================ */

const ROWS = [
  ["link", "the connection"],
  ["seq", "frames numbered"],
  ["seen", "frames arrived"],
  ["drop", "dropped by the server"],
  ["src", "sources on the wire"]
];

export function create(host) {
  const el = host.el;
  const feed = host.feed;

  const cell = {};
  const table = document.createElement("div");
  table.className = "wire-rows";

  for (const [key, label] of ROWS) {
    const k = document.createElement("div");
    k.className = "wire-k";
    k.textContent = label;
    const v = document.createElement("div");
    v.className = "wire-v";
    v.textContent = "…";
    cell[key] = v;
    table.appendChild(k);
    table.appendChild(v);
  }
  el.appendChild(table);

  if (!feed) {
    cell.link.textContent = "no feed on this page";
    return {};
  }

  /* Counted here rather than taken from the sequence number, because the two
     disagree in the way that is worth seeing: seq is what the server numbered
     and `seen` is what arrived. A gap between them, held over several ticks,
     is the same story `dropped` tells from the other end. */
  let seen = 0;
  const off = feed.on("*", function () { seen++; });

  function draw() {
    const s = feed.status();

    /* A recording has nothing to be disconnected from, and saying "open"
       about one is this card answering a question nobody asked. It reports
       what it is watching instead — which on a player is the thing a reader
       most needs to be reminded of, because the board looks identical. */
    if (s.replay) {
      cell.link.textContent = s.playing ? "a recording · playing" : "a recording · paused";
      cell.link.className = "wire-v";
    } else {
      cell.link.textContent = s.open ? "open" : "closed — retrying";
      cell.link.className = "wire-v " + (s.open ? "is-ok" : "is-bad");
    }

    cell.seq.textContent = String(s.seq || 0);
    cell.seen.textContent = String(seen);

    const dropped = s.dropped || 0;
    cell.drop.textContent = dropped ? dropped + " — there is a gap" : "0";
    cell.drop.className = "wire-v " + (dropped ? "is-bad" : "is-ok");

    /* The server's own list, which is longer than the always-on six whenever
       something asked for a capture or a log tail. Before the first hello
       there is nothing honest to print. */
    cell.src.textContent = s.sources ? s.sources.join(" · ") : "…";
  }

  draw();

  /* A second. The polled sources tick every three, so this is fast enough to
     make a reconnect visible and slow enough that a card costs nothing. */
  const timer = setInterval(draw, 1000);

  return {
    destroy: function () {
      clearInterval(timer);
      off();
    }
  };
}
