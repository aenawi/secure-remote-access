/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   Does the UI JavaScript parse?

   Three thousand lines of it are shipped as written — `//go:embed ui` puts
   app.js and hud/ inside the control binary, and the guide's assets/ are
   served straight off disk. Nothing here compiles, bundles or minifies,
   which is a decision worth keeping: it is why `docker compose up` is the
   only prerequisite. It also means a stray comma reaches the browser.

   And the browser is quiet about it in exactly the wrong way. `run()` in
   hud/setpieces.js wraps every shot in a try/catch so a broken set-piece
   cannot take the page down; app.js falls back to the text trace. To
   anyone driving the lab, a typo therefore looks almost exactly like an
   action that never had a set-piece — which is how `rotate-key` went a
   release with nothing drawn and nothing said.

   This is the cheapest possible answer to that: `node --check` over each
   file, in the same goal the browser loads it in. It runs no code, needs
   no packages, and takes about a tenth of a second.

       node checks/syntax.mjs

   `make check` runs it, and skips it with a note when Node is absent,
   because Docker is the only thing the lab requires and that does not
   change for a linter.
   ============================================================ */

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/* Goal matters: app.js and the guide's assets are classic scripts loaded
   with a bare <script src>, and hud/ is ES modules because three.js is one.
   Checking a module as a script reports every `import` as a syntax error,
   so each file is checked as what it actually is.

   hud/three.module.js is not in this list on purpose. It is three.js r166,
   vendored and minified: a parse error in it means a bad copy, not a typo,
   and nothing in this repo would fix it by hand. */
const FILES = [
  ["lab/control/ui/app.js",              "commonjs"],
  ["lab/control/ui/hud/scene.js",        "module"],
  ["lab/control/ui/hud/setpieces.js",    "module"],
  ["lab/control/ui/hud/reading.js",      "module"],
  ["assets/app.js",                      "commonjs"],
  ["assets/anim.js",                     "commonjs"],
  ["assets/nav.js",                      "commonjs"],
  ["assets/sandbox.js",                  "commonjs"]
];

let failed = 0;

for (const [rel, goal] of FILES) {
  const src = readFileSync(join(root, rel), "utf8");
  const lines = src.split("\n").length;

  /* Through stdin rather than by path: --check picks its goal from the file
     extension, and every module here is a .js. The file name is ours to
     print, so nothing is lost by handing over the bytes. */
  const out = spawnSync(process.execPath, ["--check", "--input-type=" + goal], {
    input: src,
    encoding: "utf8"
  });

  if (out.status === 0) {
    console.log("  ok    " + rel + "  (" + lines + " lines, " + goal + ")");
    continue;
  }

  failed++;
  console.log("  FAIL  " + rel + "  (" + goal + ")");
  /* Node prints the offending line, a caret under it, and the message. The
     path in that text is [stdin]; the path that matters is above. */
  const detail = (out.stderr || "").trim().split("\n")
    .filter((l) => !/^\s*at /.test(l) && !/^Node\.js v/.test(l) && l.trim() !== "")
    .map((l) => l.replace("[stdin]", rel));
  for (const line of detail) console.log("        " + line);
}

if (failed) {
  console.log("\n" + failed + " of " + FILES.length + " files do not parse.");
  process.exit(1);
}
console.log("\nAll " + FILES.length + " files parse.");
