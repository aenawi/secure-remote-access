// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"encoding/json"
	"io/fs"
	"log"
	"path"
	"sort"
)

// ---------------------------------------------------------------------------
// HUD themes
//
// The board has always read its colours off the page rather than carrying a
// palette of its own — readTokens() in hud/scene.js pulls nine custom
// properties and paints from them. That was done so the light/dark button
// could move the board with it, and it is the whole mechanism a theme needs:
// redefine the nine, tell the board they moved.
//
// So a theme is a folder under ui/hud/themes/ with two files in it. theme.css
// redefines whichever of the nine it cares about, scoped to
// :root[data-hud-theme="<id>"] so it is inert until selected. theme.json says
// what it is called and which ground it was drawn for.
//
// This file is the half that finds them. It walks the embedded UI at startup
// so the page does not have to be told what exists — adding a theme is a
// folder and a rebuild, not an edit to a list in three places. Which is the
// same reason panels.go exists: the server holds the spec, the UI renders
// whatever it is handed.
//
// A theme that does not parse, or whose id disagrees with its folder, is
// skipped with a line at the console rather than taken as a reason to refuse
// to start. That is the choice setpieces.go's missing() already makes and for
// the same reason: a broken extra must not take the lab with it, and a silent
// one is how `rotate-key` went a release with nothing drawn.
// ---------------------------------------------------------------------------

// Theme is one entry in the store, as /api/themes serves it.
type Theme struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Note string `json:"note"`
	// Ground is the page background the theme was drawn against: "light",
	// "dark", or "any" for one that works on either. It is advisory — selecting
	// a theme that names a ground moves the page to it, and the light/dark
	// button still wins afterwards.
	Ground string `json:"ground"`
	Author string `json:"author"`
}

// themesDir is where the store lives inside the UI filesystem. It is a
// constant rather than a flag because the UI is //go:embed-ed: nothing can put
// a theme anywhere else without rebuilding the binary, which is the point.
const themesDir = "hud/themes"

// baseTheme is the one that must exist. It overrides nothing — it is the
// guide's own palette, which is what the board looked like before there was a
// store — so it is also the fallback when a saved id no longer resolves.
const baseTheme = "chapter"

var validGrounds = map[string]bool{"light": true, "dark": true, "any": true}

// loadThemes walks fsys for ui/hud/themes/*/theme.json and returns what it
// finds, base theme first and the rest alphabetically by name.
//
// fsys is the UI sub-filesystem, so paths here start at hud/.
func loadThemes(fsys fs.FS) []Theme {
	entries, err := fs.ReadDir(fsys, themesDir)
	if err != nil {
		log.Printf("hud themes: %s is not readable (%v), so the store is empty", themesDir, err)
		return nil
	}

	var out []Theme
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		t, ok := readTheme(fsys, e.Name())
		if !ok {
			continue
		}
		out = append(out, t)
	}

	sort.Slice(out, func(i, j int) bool {
		if (out[i].ID == baseTheme) != (out[j].ID == baseTheme) {
			return out[i].ID == baseTheme
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// readTheme reads one folder, and says why it skipped it when it does.
//
// The id has to match the folder name because the folder name is what the
// page builds the stylesheet URL from. A theme whose json claimed a different
// id would load one file and select another, and the failure would be a board
// that keeps the previous palette with no error anywhere.
func readTheme(fsys fs.FS, dir string) (Theme, bool) {
	b, err := fs.ReadFile(fsys, path.Join(themesDir, dir, "theme.json"))
	if err != nil {
		log.Printf("hud theme %q: no theme.json, skipped", dir)
		return Theme{}, false
	}
	var t Theme
	if err := json.Unmarshal(b, &t); err != nil {
		log.Printf("hud theme %q: theme.json does not parse (%v), skipped", dir, err)
		return Theme{}, false
	}
	if t.ID != dir {
		log.Printf("hud theme %q: theme.json says id %q, skipped", dir, t.ID)
		return Theme{}, false
	}
	if t.Name == "" {
		log.Printf("hud theme %q: no name, skipped", dir)
		return Theme{}, false
	}
	if _, err := fs.Stat(fsys, path.Join(themesDir, dir, "theme.css")); err != nil {
		log.Printf("hud theme %q: no theme.css, skipped", dir)
		return Theme{}, false
	}
	if !validGrounds[t.Ground] {
		// Not a reason to drop the theme: "any" is the honest reading of a
		// theme that did not say, and it is what the base theme is.
		log.Printf("hud theme %q: ground %q is not light, dark or any — read as any", dir, t.Ground)
		t.Ground = "any"
	}
	return t, true
}
