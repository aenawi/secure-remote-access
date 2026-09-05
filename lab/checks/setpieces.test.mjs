/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   Does the board's dispatch table still link, and is anything missing
   a shot?

   This one imports hud/setpieces.js for real — three.js and all — which
   is worth doing for a reason the parse check cannot cover: a file can
   parse perfectly and still fail the moment the browser links it, because
   an import names something the other module does not export. In the page
   that arrives as a module that never evaluates and a board that never
   appears, with the error in a console nobody has open.

   `missing()` is the other half. It is what app.js calls at startup with
   the server's dispatch table, and it is the whole of ticket 33: both
   `rotate-key` and `outage` are posted to /api/action without being in
   AttackList, so a check walking the attack list could not see them
   however carefully it was written — and one of them went a release with
   no set-piece while the page said nothing.

   The two failures are told apart on purpose. A SyntaxError from the
   import is a link failure — a name that does not exist — and that is ours
   and it fails here. Anything else is three.js wanting a browser Node
   cannot give it, and the rest skip rather than fail, because this file is
   here to catch our mistakes and not to assert that Node runs a renderer.
   ============================================================ */

import test from "node:test";
import assert from "node:assert/strict";

let hud = null, linkError = "", browserOnly = "";
try {
  hud = await import("../control/ui/hud/setpieces.js");
} catch (e) {
  /* "does not provide an export named X" arrives as a SyntaxError, at link
     time, from a file that parses perfectly. It is the one break the parse
     check in syntax.mjs cannot see. */
  if (e && e.name === "SyntaxError") linkError = e.message;
  else browserOnly = "hud/ does not evaluate outside a browser here: " + e.message;
}
const needsBrowser = hud ? false : (browserOnly || false);

test("hud/ links — every import names something that is exported", () => {
  assert.equal(linkError, "", "hud/setpieces.js failed to link: " + linkError);
});

test("every set-piece in the table is a function", { skip: needsBrowser }, () => {
  const ids = Object.keys(hud.SETPIECES);
  assert.ok(ids.length >= 11, "nine attacks, plus outage and rotate-key");
  for (const id of ids) {
    assert.equal(typeof hud.SETPIECES[id], "function", id + " is not a function");
    assert.equal(hud.hasSetpiece(id), true);
  }
});

test("the two that are not attacks are still on the board", { skip: needsBrowser }, () => {
  /* Neither is in AttackList. Both are dispatchable. That is exactly the
     gap that went unreported for a release. */
  assert.equal(hud.hasSetpiece("outage"), true);
  assert.equal(hud.hasSetpiece("rotate-key"), true);
});

test("missing() names the ids with no shot, and nothing else", { skip: needsBrowser }, () => {
  assert.deepEqual(hud.missing(["scan-public", "outage", "rotate-key"]), []);
  assert.deepEqual(hud.missing(["scan-public", "brand-new-attack"]), ["brand-new-attack"]);
  /* Ids or AttackList-shaped objects both work, because being strict about
     the shape here would only ever turn a report back into a silence. */
  assert.deepEqual(hud.missing([{ id: "sniff" }, { id: "brand-new-attack" }]),
                   ["brand-new-attack"]);
  assert.deepEqual(hud.missing(null), []);
  assert.deepEqual(hud.missing([null, "", {}]), []);
});

test("hasSetpiece is not fooled by what every object inherits",
     { skip: needsBrowser }, () => {
  /* "constructor" and "toString" are on Object.prototype. A plain `in` or a
     truthiness test here would report a set-piece that does not exist, and
     run() would then try to call one. */
  assert.equal(hud.hasSetpiece("constructor"), false);
  assert.equal(hud.hasSetpiece("toString"), false);
  assert.deepEqual(hud.missing(["constructor"]), ["constructor"]);
});
