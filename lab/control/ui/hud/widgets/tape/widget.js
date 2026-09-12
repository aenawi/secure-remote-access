/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   The tape.

   One line per frame, newest at the top, with the sequence number the server
   gave it. It is the wire written down — which makes it the closest thing on
   the page to what a recording will hold, and the cheapest way to find out
   whether an event somebody wants to replay is actually on the feed.

   The three polled sources are hidden by default, and that is a decision
   taken from watching it run rather than from reading the type list. `stat`,
   `status` and `netcheck` are re-read every three seconds whether or not
   anything changed, and `tailscale netcheck` is a screenful; with them in,
   one probe put nineteen lines on the tape and two of them were the probe.
   The default is the frames that mean the lab did something — a verdict, a
   flow, a packet, a log line, a configuration change — and `hide: []` puts
   the polls back for anyone watching the polling itself.

   Newest at the top rather than a tail that scrolls: a tape the reader has
   to keep scrolling to the bottom of fights them for as long as the lab is
   running, and there is nothing here that needs to be read in order.

   Options:
     limit   how many lines to keep. Default 40, clamped to 1..500.
     hide    event types to leave out. Default ["stat", "status", "netcheck"].
   ============================================================ */

const DEFAULT_LIMIT = 40;
const DEFAULT_HIDE = ["stat", "status", "netcheck"];

export function create(host) {
  const el = host.el;
  const feed = host.feed;
  const options = host.options || {};

  const limit = clamp(options.limit, 1, 500, DEFAULT_LIMIT);
  const hide = new Set(Array.isArray(options.hide) ? options.hide : DEFAULT_HIDE);

  const list = document.createElement("div");
  list.className = "tape-lines";
  el.appendChild(list);

  /* An empty box reads as a broken one, and with the polls hidden this card
     is empty until the lab is asked to do something — which on a freshly
     loaded page is a while. So it says what it is waiting for, and the line
     goes the moment there is a frame to replace it with. */
  const waiting = document.createElement("div");
  waiting.className = "tape-waiting";
  waiting.textContent = feed
    ? "waiting for the lab to do something"
    : "no feed on this page";
  list.appendChild(waiting);

  if (!feed) return {};

  const off = feed.on("*", function (data, ev) {
    if (hide.has(ev.type)) return;
    if (waiting.parentNode) list.removeChild(waiting);

    const line = document.createElement("div");
    line.className = "tape-line";
    line.dataset.type = ev.type;

    const seq = document.createElement("span");
    seq.className = "tape-seq";
    seq.textContent = pad(ev.seq);

    const type = document.createElement("span");
    type.className = "tape-type";
    type.textContent = ev.type;

    const said = document.createElement("span");
    said.className = "tape-said";
    said.textContent = summarise(ev.type, data);

    line.appendChild(seq);
    line.appendChild(type);
    line.appendChild(said);

    list.insertBefore(line, list.firstChild);
    while (list.childNodes.length > limit) list.removeChild(list.lastChild);
  });

  return { destroy: off };
}

/* One line, in the terms the type is about. A frame the reader cannot tell
   apart from the one above it is a frame that did not need a line, so every
   type says the thing that distinguishes one of its frames from the next. */
function summarise(type, data) {
  const d = data || {};
  switch (type) {
    case "hello":
      return (d.types ? d.types.length : 0) + " types, " + (d.sources ? d.sources.length : 0) + " sources";
    case "verdict":
      return d.id + " — " + (d.result && d.result.ok ? "allowed" : "denied") +
        rung(d.result) + " · " + (d.result ? d.result.rule || "" : "");
    case "flow":
      return (d.result ? d.result.from + " → " + d.result.to + ":" + d.result.port : d.id) +
        " — " + (d.result && d.result.ok ? "reached" : "stopped") + rung(d.result) +
        (d.result && d.result.path ? " · " + d.result.path : "");
    case "packet":
    case "log":
      return clip(d.line, 120);
    case "note":
      return d.source + ": " + clip(d.line, 100);
    case "stat":
      return (Array.isArray(data) ? data.length : 0) + " containers sampled";
    case "state":
      /* The whole snapshot, and printing any one field of it invites the
         reader to think that field is why the frame was sent. It is sent on
         change, and which field changed is not in the frame. */
      return "the configuration changed";
    case "status":
    case "netcheck":
      return clip(oneLine(d.text), 120);
    default:
      return "";
  }
}

function rung(res) {
  return res && res.rung ? " at rung " + res.rung : "";
}

function oneLine(s) {
  return typeof s === "string" ? s.replace(/\s+/g, " ").trim() : "";
}

function clip(s, n) {
  const t = typeof s === "string" ? s : "";
  return t.length > n ? t.slice(0, n - 1) + "…" : t;
}

function pad(n) {
  return typeof n === "number" ? String(n).padStart(4, "0") : "----";
}

function clamp(v, lo, hi, def) {
  const n = typeof v === "number" ? v : parseInt(v, 10);
  if (!isFinite(n)) return def;
  return Math.max(lo, Math.min(hi, Math.round(n)));
}
