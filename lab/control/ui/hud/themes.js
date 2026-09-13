/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   The HUD theme store.

   A theme is a folder under hud/themes/ holding theme.css and theme.json.
   themes.go walks the embedded UI and serves what it found at /api/themes,
   so nothing here carries a list: the server knows, and this asks.

   Selecting a theme does three things and no more.

     1. Make sure the theme's stylesheet is in the document. Every theme's
        rules are scoped to :root[data-hud-theme="<id>"], so a sheet that has
        been loaded and then deselected is inert rather than removed. Loading
        is one-way, which keeps switching back instant and keeps this file
        free of the question of when a <link> is safe to drop.

     2. Set data-hud-theme on the root element, and — if the theme named a
        ground — move data-theme to it. Advisory, as themes.go says: the
        light/dark button still wins afterwards, because a reader who presses
        it has said something more recent than the theme's manifest did.

     3. Tell the board its colours moved. scene.js reads the nine --board-*
        properties once and paints from what it read, so nothing changes on
        screen until refreshTokens() is called. This is the same call the
        light/dark button already makes.

   Every entry point survives having no board, no server and no localStorage,
   because the page it belongs to does. A control surface that will not draw
   because a stylesheet 404'd is a worse failure than an unthemed board.
   ============================================================ */

const BASE = "chapter";           /* matches baseTheme in themes.go */
const STORE_KEY = "lab-hud-theme";

/* Which stylesheets have been put in the document, by id. */
const loaded = new Set();

let catalog = [];
let active = BASE;

/* ---------- what exists ---------------------------------------- */

/* The store, as the server found it. Empty until load() has run, which is
   the honest answer before then rather than a guess. */
export function list() { return catalog.slice(); }

/* The id currently selected. */
export function current() { return active; }

/* One entry by id, or null. */
export function get(id) {
  for (const t of catalog) if (t.id === id) return t;
  return null;
}

/* Ask the server what it embedded. A failure here is not fatal: the base
   theme overrides nothing, so a page with no catalog still draws the board
   exactly as it did before this file existed. */
export async function load() {
  try {
    const res = await fetch("/api/themes", { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const body = await res.json();
    catalog = Array.isArray(body) ? body : [];
  } catch (e) {
    console.warn("hud themes: /api/themes did not answer (" + e.message + "), staying on " + BASE);
    catalog = [];
  }
  return list();
}

/* Hand the store over rather than asking for it.
 *
 * The player page has no server to ask. A recording carries the store in its
 * opening hello — see Page in lab/control/feed.go — precisely so that a
 * captured attack can be watched with the cards the theme docked, and this is
 * where that list goes in. Everything after it is identical: the stylesheets
 * are still fetched by relative path, because the player is served from the
 * same directory the live page is.
 *
 * Returns what was accepted, so a caller can see whether the recording
 * carried anything at all. */
export function seed(store) {
  catalog = Array.isArray(store) ? store.slice() : [];
  return list();
}

/* ---------- selecting one -------------------------------------- */

/* Put a theme's stylesheet in the document, and resolve when the browser has
   parsed it. The wait matters: refreshTokens() reads computed values, and a
   board told to repaint before its palette landed paints the old one and has
   no reason to try again.

   A sheet that fails to load resolves too. The rules simply never apply, the
   board keeps the palette it had, and the console says which file was
   missing — which is a readable board and a legible complaint, rather than a
   promise that never settles. */
function ensureSheet(id) {
  if (loaded.has(id)) return Promise.resolve();
  return new Promise((resolve) => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "hud/themes/" + encodeURIComponent(id) + "/theme.css";
    link.dataset.hudTheme = id;
    link.addEventListener("load", () => { loaded.add(id); resolve(); });
    link.addEventListener("error", () => {
      console.warn("hud theme " + id + ": theme.css did not load, the board keeps its colours");
      /* Marked loaded on purpose: retrying on every switch would add one dead
         <link> per press for as long as the file is missing. */
      loaded.add(id);
      resolve();
    });
    document.head.appendChild(link);
  });
}

/* Select a theme. `board` may be null — the page runs without one whenever
   WebGL is unavailable, and the attribute is still worth setting so anything
   else styled off it agrees with the picker. */
export async function apply(id, board) {
  const theme = get(id) || get(BASE);
  const next = theme ? theme.id : BASE;

  await ensureSheet(next);
  document.documentElement.setAttribute("data-hud-theme", next);

  if (theme && (theme.ground === "light" || theme.ground === "dark")) {
    document.documentElement.setAttribute("data-theme", theme.ground);
    try { localStorage.setItem("lab-theme", theme.ground); } catch (e) { /* private mode */ }
  }

  active = next;
  try { localStorage.setItem(STORE_KEY, next); } catch (e) { /* private mode */ }

  if (board) board.refreshTokens();
  return next;
}

/* ---------- starting up ---------------------------------------- */

/* Read the catalog, then select whatever was chosen last — falling back to
   the base theme when the saved id names a theme that is no longer embedded,
   which is what happens the first time somebody removes a folder.

   Returns the id that ended up applied, so a caller can set its picker from
   the answer rather than from what it asked for.

   `store` is for the player page: hand it the list a recording carried and
   nothing is fetched. The rest of this function is the part worth sharing —
   remembering which theme the reader picked, and noticing when the saved id
   names a theme that is not in front of it. Both pages want that and neither
   should own a copy of it. */
export async function init(board, store) {
  if (store) seed(store);
  else await load();

  let saved = null;
  try { saved = localStorage.getItem(STORE_KEY); } catch (e) { /* private mode */ }

  if (saved && !get(saved)) {
    console.warn("hud themes: " + saved + " is no longer embedded, falling back to " + BASE);
    saved = null;
  }
  return apply(saved || BASE, board);
}
