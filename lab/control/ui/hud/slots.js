/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   Widgets and slots.

   The page has four docks around the board — top, left, right, bottom — and
   a dock holds cards. This file builds them, and it is the only thing that
   knows how a card becomes a widget.

   What a widget gets is the whole seam, and it is deliberately tiny:

       export function create({ el, feed, options }) {
         ...
         return { destroy() {} };          // optional
       }

     el       a div. The card's body, already in the document and sized.
              Yours until destroy() — nothing else writes into it.
     feed     window.LabFeed. on(type, fn) for the always-on sources,
              want(sources) for a capture or a log tail. Both hand back a
              function that undoes them, and a widget that calls neither in
              destroy() is a widget that leaks.
     options  whatever the theme's placement carried, verbatim. Yours to
              read and yours to ignore.

   And that is all. No board object, no page elements, no controller. The
   board is twenty-five coupled methods over 1300 lines of three.js, and
   publishing it as a plugin API would freeze hud/scene.js the day somebody
   wrote against it. A widget that wants to know what the lab is doing reads
   the feed, which is what the feed is for.

   The board is not a card and does not live here. It is the floor of the
   window — app.js creates it, drives it, and tells it how much of itself the
   furniture is covering. This file's part in that is covered(): the docks
   report what they hide, app.js adds it to what the rails hide, and the
   camera aims at the gap that is left. It reports to the camera and not to
   the stylesheet on purpose: the docks are positioned from --pad-*, so
   feeding their size back into --pad-* would be a layout that never settles.

   Nothing here throws at a caller and nothing here is required. A widget
   that will not import leaves a card saying so and the other cards mount; a
   layout that is empty builds no layer at all, which is the page exactly as
   it was before this file existed.
   ============================================================ */

/* The docks, in the order they are built. Matches validSlots in widgets.go —
   the server drops a placement aimed at anything else, so a name that
   reaches this file is one of these. */
export const SLOTS = ["top", "left", "right", "bottom"];

let layer = null;         /* the .slots element, or null when nothing is docked */
let docks = {};           /* slot -> the dock element */
let live = [];            /* [{ placement, card, instance }] */
let generation = 0;       /* which apply() is the current one */
let observer = null;      /* watches the docks for a card changing size */

let feed = null;
let onLayout = function () {};

/* ---------- starting up ---------------------------------------- */

/* Told once, by the page. `feed` is handed on rather than read off window
   here so a test — or a second board in one document — can pass its own.

   onLayout is called after the cards of an apply() have mounted, because
   that is when covered() starts answering differently and the camera needs
   to be told. */
export function init(options) {
  const o = options || {};
  feed = o.feed || (typeof window !== "undefined" ? window.LabFeed : null) || null;
  if (typeof o.onLayout === "function") onLayout = o.onLayout;
}

/* ---------- what is docked ------------------------------------- */

/* The placements that actually built something, in mount order. For a test,
   and for anybody asking the page what it is showing. */
export function list() {
  return live.map((w) => ({ widget: w.placement.widget, slot: w.placement.slot }));
}

/* How much of `within` each dock hides, in CSS pixels from that edge.
 *
 * `within` is the rectangle being covered — the board's viewport, when app.js
 * asks. Overlap with it rather than the dock's own width, and measured from
 * the live elements rather than added up from the cards, because a dock that
 * wrapped or a card shorter than its content covers what it covers and not
 * what it asked for. It is the same sum measureRails() does for the rails,
 * against the same rectangle, so the two answers can simply be compared.
 *
 * An empty dock is zero. The docks have no background of their own, so a dock
 * with nothing in it is not in the way of anything. */
export function covered(within) {
  const out = { left: 0, right: 0, top: 0, bottom: 0 };
  if (!layer) return out;
  const box = within || layer.getBoundingClientRect();

  for (const slot of SLOTS) {
    const dock = docks[slot];
    if (!dock || !dock.firstChild) continue;
    const r = dock.getBoundingClientRect();
    if (slot === "left") out.left = Math.max(0, Math.round(r.right - box.left));
    if (slot === "right") out.right = Math.max(0, Math.round(box.right - r.left));
    if (slot === "top") out.top = Math.max(0, Math.round(r.bottom - box.top));
    if (slot === "bottom") out.bottom = Math.max(0, Math.round(box.bottom - r.top));
  }
  return out;
}

/* ---------- building it ---------------------------------------- */

/* Unmount everything and build `layout` instead.
 *
 * This is what a theme switch calls, and a theme switch can happen twice
 * before the first import has resolved — a reader holding the arrow keys in
 * the picker does exactly that. So each call takes a generation, and a card
 * whose generation is no longer the current one is thrown away rather than
 * appended. Without it the docks end up holding the union of every theme
 * that was passed through.
 *
 * Returns the number of cards that mounted, which is not always the number
 * asked for: a widget that fails to import is reported on its card and
 * counted as a miss. */
export async function apply(layout) {
  const mine = ++generation;
  clear();

  const wanted = Array.isArray(layout) ? layout.filter(usable) : [];
  if (!wanted.length) {
    onLayout();
    return 0;
  }

  build();

  /* Every module at once rather than one after another: they are four small
     files off the same origin, and awaiting them in series makes the last
     card land four round trips late for no reason. */
  const loaded = await Promise.all(wanted.map(load));
  if (mine !== generation) return 0;      /* a newer apply() owns the layer */

  let mounted = 0;
  for (let i = 0; i < wanted.length; i++) {
    if (mount(wanted[i], loaded[i])) mounted++;
  }

  onLayout();
  return mounted;
}

/* Take the layer down. Every widget is told before its DOM goes, because a
   widget that registered a feed listener has to be given the chance to drop
   it — and a listener left behind is a listener writing into a div that is
   no longer in the document. */
export function clear() {
  for (const w of live) {
    if (!w.instance || typeof w.instance.destroy !== "function") continue;
    try {
      w.instance.destroy();
    } catch (e) {
      console.error("widget " + w.placement.widget + " threw on destroy: " + e);
    }
  }
  live = [];

  if (observer) {
    observer.disconnect();
    observer = null;
  }
  if (layer && layer.parentNode) layer.parentNode.removeChild(layer);
  layer = null;
  docks = {};
}

/* A placement the server has already pruned should be well-formed, so this is
   a guard against a hand-edited response rather than a validation pass. */
function usable(p) {
  return !!(p && typeof p.widget === "string" && p.widget && SLOTS.indexOf(p.slot) >= 0);
}

/* The layer and its four docks. Built on demand and removed when empty, so a
   theme that docks nothing leaves no element over the board at all — an
   invisible div that swallows a drag is the worst version of this file. */
function build() {
  layer = document.createElement("div");
  layer.className = "slots";
  layer.id = "slots";

  for (const slot of SLOTS) {
    const dock = document.createElement("div");
    dock.className = "dock dock-" + slot;
    dock.dataset.slot = slot;
    docks[slot] = dock;
    layer.appendChild(dock);
  }

  const app = document.querySelector(".app") || document.body;
  app.appendChild(layer);

  /* A card changes size after it mounts — a tape fills up, a verdict line
     wraps — and every one of those changes what the docks are covering. The
     camera is aimed at the gap the docks leave, so it has to be told, and
     nothing else on the page would notice.

     Safe against a loop by construction: onLayout re-measures and moves the
     camera, and the camera cannot resize a card. */
  if (typeof ResizeObserver === "function") {
    observer = new ResizeObserver(function () { onLayout(); });
    for (const slot of SLOTS) observer.observe(docks[slot]);
  }
}

/* Which widgets have had their stylesheet put in the document, by id. */
const sheets = new Set();

/* Put a widget's stylesheet in the document. One way, like the theme store's:
   every rule in it is scoped to .card[data-widget="<id>"], so a sheet that
   has been loaded and then undocked is inert rather than something this file
   has to decide when it is safe to remove.

   widgets.go requires the file, so a widget that was served has one. A sheet
   that fails to load anyway resolves too — an unstyled card is a readable
   card, and a card that never appears because a stylesheet 404'd is not. */
function ensureSheet(id) {
  if (sheets.has(id)) return Promise.resolve();
  sheets.add(id);
  return new Promise((resolve) => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "hud/widgets/" + encodeURIComponent(id) + "/widget.css";
    link.dataset.hudWidget = id;
    link.addEventListener("load", resolve);
    link.addEventListener("error", () => {
      console.warn("widget " + id + ": widget.css did not load, the card is unstyled");
      resolve();
    });
    document.head.appendChild(link);
  });
}

/* Import one widget's module, and its stylesheet with it.
 *
 * The sheet is waited for rather than fired off: a widget that measures its
 * own body — and a tape that wants to know how many lines fit is the obvious
 * one — would otherwise measure it at whatever size an unstyled div happens
 * to be.
 *
 * A failure resolves to null rather than rejecting: one missing file must not
 * take the rest of the layout with it, and the card it was going to fill is
 * where the complaint goes. */
function load(placement) {
  const id = placement.widget;
  const module = import("./widgets/" + encodeURIComponent(id) + "/widget.js")
    .catch((e) => {
      console.warn("widget " + id + ": did not load (" + e.message + ")");
      return null;
    });
  return Promise.all([module, ensureSheet(id)]).then((both) => both[0]);
}

/* Build one card and hand its body to the widget.
 *
 * A widget that throws in create() has its card left saying so. That is a
 * deliberate change of tone from the rest of the page, which fails quietly:
 * a broken set-piece looks like an action that never had one, and that cost
 * this project a release. A card is a box with a name on it, so an empty one
 * is already a visible question — answering it in the box is cheaper than
 * asking somebody to open the console. */
function mount(placement, module) {
  const name = placement.widget;
  const card = document.createElement("section");
  card.className = "card glass";
  card.dataset.widget = name;

  const head = document.createElement("div");
  head.className = "card-head";
  const title = document.createElement("span");
  title.className = "card-t";
  title.textContent = placement.title || name;
  head.appendChild(title);

  const body = document.createElement("div");
  body.className = "card-body";

  card.appendChild(head);
  card.appendChild(body);
  docks[placement.slot].appendChild(card);

  if (!module || typeof module.create !== "function") {
    fail(body, module ? "no create()" : "did not load");
    return false;
  }

  let instance = null;
  try {
    instance = module.create({
      el: body,
      feed: feed,
      options: placement.options || {}
    });
  } catch (e) {
    console.error("widget " + name + " threw on create: " + e);
    fail(body, "threw while starting");
    return false;
  }

  live.push({ placement: placement, card: card, instance: instance || null });
  return true;
}

function fail(body, why) {
  body.classList.add("card-dead");
  body.textContent = why;
}
