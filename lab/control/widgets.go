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
// Widgets and slots
//
// The page has four docks around the board — top, left, right, bottom — and a
// dock holds cards. A card is a widget: a folder under ui/hud/widgets/ with a
// widget.js in it, which is handed a div and the feed and told to draw.
//
// This file is the half that finds them, and it is deliberately the same
// shape as themes.go: walk the embedded UI at startup, skip anything
// malformed with a line at the console, serve what is left at /api/widgets.
// Adding a widget is a folder and a rebuild, not an edit to a list in three
// places — the same property panels.go and the theme store already have.
//
// What goes where is not in here. A widget says which docks it fits in; a
// theme's theme.json says which ones are actually placed and in what order.
// That split is the point of the branch: the page's furniture is data, so a
// theme can rearrange the instrument without touching index.html.
//
// The board is not in this list. It is the floor of the window rather than a
// card in a dock, app.js creates it and drives it by hand, and the slot it
// sits in is host-owned — the layer knows its rectangle so cards stay off it,
// and that is all. Making the board a widget under the same contract as these
// means the board reading the feed instead of being called, which is the next
// piece of work and not this one. A privileged contract that handed a widget
// the twenty-five method board object would freeze hud/scene.js in place, so
// there is no such contract here.
// ---------------------------------------------------------------------------

// Widget is one entry in the registry, as /api/widgets serves it.
type Widget struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Note string `json:"note"`
	// Slots are the docks this widget is willing to sit in. A placement into
	// a dock that is not listed is dropped: a tape of every frame on the wire
	// wants a tall column and reads as nonsense in a 90px bottom strip, and
	// the widget is the thing that knows that.
	Slots  []string `json:"slots"`
	Author string   `json:"author"`
}

// widgetsDir is where the registry lives inside the UI filesystem. Constant
// for the same reason themesDir is: the UI is //go:embed-ed, so nothing can
// put a widget anywhere else without rebuilding the binary. The control
// server holds the Docker socket and has no authentication, which makes
// loading page JavaScript off disk a real risk rather than a theoretical one.
const widgetsDir = "hud/widgets"

// The docks a widget may ask for. "board" is not one of them — see the note
// at the top of this file.
var validSlots = map[string]bool{
	"top":    true,
	"left":   true,
	"right":  true,
	"bottom": true,
}

// loadWidgets walks fsys for ui/hud/widgets/*/widget.json and returns what it
// finds, alphabetically by name.
//
// fsys is the UI sub-filesystem, so paths here start at hud/.
func loadWidgets(fsys fs.FS) []Widget {
	entries, err := fs.ReadDir(fsys, widgetsDir)
	if err != nil {
		log.Printf("hud widgets: %s is not readable (%v), so the registry is empty", widgetsDir, err)
		return nil
	}

	var out []Widget
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		w, ok := readWidget(fsys, e.Name())
		if !ok {
			continue
		}
		out = append(out, w)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// readWidget reads one folder, and says why it skipped it when it does.
//
// The id has to match the folder name because the folder name is what the
// page builds the module URL from. A widget whose json claimed a different id
// would be placed under one name and imported from another, and the failure
// would be an empty card with a 404 in the network tab and nothing in the
// console that named the theme that asked for it.
func readWidget(fsys fs.FS, dir string) (Widget, bool) {
	b, err := fs.ReadFile(fsys, path.Join(widgetsDir, dir, "widget.json"))
	if err != nil {
		log.Printf("hud widget %q: no widget.json, skipped", dir)
		return Widget{}, false
	}
	var w Widget
	if err := json.Unmarshal(b, &w); err != nil {
		log.Printf("hud widget %q: widget.json does not parse (%v), skipped", dir, err)
		return Widget{}, false
	}
	if w.ID != dir {
		log.Printf("hud widget %q: widget.json says id %q, skipped", dir, w.ID)
		return Widget{}, false
	}
	if w.Name == "" {
		log.Printf("hud widget %q: no name, skipped", dir)
		return Widget{}, false
	}
	if _, err := fs.Stat(fsys, path.Join(widgetsDir, dir, "widget.js")); err != nil {
		log.Printf("hud widget %q: no widget.js, skipped", dir)
		return Widget{}, false
	}

	// Required, and an empty one is fine. A widget brings its own styling
	// because the alternative is style.css carrying a block per widget, which
	// puts the host back in the business of knowing what exists — the thing
	// this file was written to stop. Requiring the file rather than probing
	// for it is what lets slots.js load it unconditionally: a widget the
	// server served has a stylesheet, so there is no 404 to explain and no
	// optional path to get wrong.
	if _, err := fs.Stat(fsys, path.Join(widgetsDir, dir, "widget.css")); err != nil {
		log.Printf("hud widget %q: no widget.css, skipped (an empty one is fine)", dir)
		return Widget{}, false
	}

	// An unknown dock is dropped rather than taken as a reason to drop the
	// widget: a widget listing "sidebar" alongside "left" is a widget written
	// against a slot name this build does not have, and the half of it that
	// still makes sense is worth keeping.
	var slots []string
	for _, s := range w.Slots {
		if !validSlots[s] {
			log.Printf("hud widget %q: slot %q is not a dock, ignored", dir, s)
			continue
		}
		slots = append(slots, s)
	}
	if len(slots) == 0 {
		log.Printf("hud widget %q: no slot it fits in, skipped", dir)
		return Widget{}, false
	}
	w.Slots = slots

	return w, true
}

// resolvePlacements drops every placement that cannot be honoured, and says
// which and why.
//
// A theme is parsed without knowing what is in the registry — themes.go can
// tell that a slot name is wrong, but not that a widget is missing — so this
// is the pass that puts the two halves together. It runs once at startup,
// which means the layout the page is handed is already true: the page mounts
// what it is given and never has to decide what to do about a card it cannot
// build.
//
// The themes are returned rather than mutated in place so the caller's
// assignment is where the pruning visibly happens.
func resolvePlacements(themes []Theme, widgets []Widget) []Theme {
	fits := map[string]map[string]bool{}
	for _, w := range widgets {
		slots := map[string]bool{}
		for _, s := range w.Slots {
			slots[s] = true
		}
		fits[w.ID] = slots
	}

	out := make([]Theme, 0, len(themes))
	for _, th := range themes {
		var kept []Placement
		for _, p := range th.Layout {
			slots, known := fits[p.Widget]
			if !known {
				log.Printf("hud theme %q: widget %q is not embedded, placement dropped", th.ID, p.Widget)
				continue
			}
			if !slots[p.Slot] {
				log.Printf("hud theme %q: widget %q does not fit the %q dock, placement dropped", th.ID, p.Widget, p.Slot)
				continue
			}
			kept = append(kept, p)
		}
		th.Layout = kept
		out = append(out, th)
	}
	return out
}
