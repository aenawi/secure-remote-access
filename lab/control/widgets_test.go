// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// Same split as themes_test.go: the questions of the form "is what shipped
// well-formed" run against the real embedded folders, and the questions about
// how a malformed one is handled run against a synthetic tree, because the
// embedded one is — and should stay — correct.

func TestEmbeddedWidgetsAreWellFormed(t *testing.T) {
	got := loadWidgets(embeddedUI(t))
	if len(got) == 0 {
		t.Fatal("no widgets were embedded; ui/hud/widgets should hold at least one")
	}

	seen := map[string]bool{}
	for _, w := range got {
		if seen[w.ID] {
			t.Errorf("widget %q appears twice", w.ID)
		}
		seen[w.ID] = true

		if w.Name == "" {
			t.Errorf("widget %q has no name, so its card would have an empty header", w.ID)
		}
		// The note is the only thing somebody browsing the registry to write
		// a theme has to go on.
		if w.Note == "" {
			t.Errorf("widget %q has no note", w.ID)
		}
		if len(w.Slots) == 0 {
			t.Errorf("widget %q fits in no dock, so nothing could place it", w.ID)
		}
		for _, s := range w.Slots {
			if !validSlots[s] {
				t.Errorf("widget %q claims slot %q, which is not a dock", w.ID, s)
			}
		}
	}
}

// The seam, asserted. A widget brings its own stylesheet, which is what keeps
// style.css from carrying a block per widget — and the price of that is that a
// widget could repaint the whole page from inside its own folder. Every
// selector is anchored to the widget's own card, and this is what says so.
//
// It is the same test, for the same reason, as the one holding a theme to the
// nine --board-* properties: the rule is only a rule while something fails
// when it is broken.
func TestWidgetStylesheetsAreScopedToTheirOwnCard(t *testing.T) {
	ui := embeddedUI(t)
	for _, w := range loadWidgets(ui) {
		b, err := fs.ReadFile(ui, widgetsDir+"/"+w.ID+"/widget.css")
		if err != nil {
			t.Errorf("widget %q: reading widget.css: %v", w.ID, err)
			continue
		}
		anchor := `[data-widget="` + w.ID + `"]`
		for _, sel := range selectors(string(b)) {
			if !strings.Contains(sel, anchor) {
				t.Errorf("widget %q: selector %q is not anchored to %s, so it styles a page it does not own",
					w.ID, sel, anchor)
			}
		}
	}
}

// Every placement in every embedded theme builds something.
//
// This is the check that matters most in this file, because the failure it
// catches is silent in a browser: a theme naming a widget that is not there
// gets a layout with that card quietly missing, and the reader has no way to
// tell that from a theme that never asked for it. Running the real loaders
// against the real folders is the only way to know that what shipped agrees
// with itself.
func TestEmbeddedThemeLayoutsAllResolve(t *testing.T) {
	ui := embeddedUI(t)
	widgets := loadWidgets(ui)
	asked := loadThemes(ui)
	kept := resolvePlacements(asked, widgets)

	if len(asked) != len(kept) {
		t.Fatalf("resolvePlacements returned %d themes, want the %d it was given", len(kept), len(asked))
	}
	for i := range asked {
		if len(asked[i].Layout) == len(kept[i].Layout) {
			continue
		}
		t.Errorf("theme %q asked for %d cards and only %d can be built; the console says which",
			asked[i].ID, len(asked[i].Layout), len(kept[i].Layout))
	}
}

// The base theme docks nothing, for the same reason its stylesheet overrides
// nothing: it is the page as it was before there was a store, and it is where
// a saved id falls back to. A fallback that rearranges the furniture is not a
// fallback.
func TestBaseThemeDocksNothing(t *testing.T) {
	for _, th := range loadThemes(embeddedUI(t)) {
		if th.ID != baseTheme {
			continue
		}
		if len(th.Layout) != 0 {
			t.Errorf("%q docks %d cards; it is meant to be the page with no cards on it",
				baseTheme, len(th.Layout))
		}
		return
	}
	t.Fatalf("%q was not found", baseTheme)
}

// ---------------------------------------------------------------------------
// What happens to a malformed one
// ---------------------------------------------------------------------------

func TestWidgetIDMustMatchItsFolder(t *testing.T) {
	got := loadWidgets(widgetTree(map[string]string{
		"good": `{"id":"good","name":"Good","slots":["left"]}`,
		"liar": `{"id":"somethingelse","name":"Liar","slots":["left"]}`,
	}))
	if len(got) != 1 || got[0].ID != "good" {
		t.Fatalf("got %v, want only the folder whose id matches it", got)
	}
}

func TestWidgetWithoutItsFilesIsSkipped(t *testing.T) {
	tree := fstest.MapFS{
		widgetsDir + "/nojs/widget.json":  {Data: []byte(`{"id":"nojs","name":"No JS","slots":["left"]}`)},
		widgetsDir + "/nojs/widget.css":   {Data: []byte("")},
		widgetsDir + "/nocss/widget.json": {Data: []byte(`{"id":"nocss","name":"No CSS","slots":["left"]}`)},
		widgetsDir + "/nocss/widget.js":   {Data: []byte("")},
	}
	if got := loadWidgets(tree); len(got) != 0 {
		t.Fatalf("got %v, want nothing: the page would ask for a file that is not there", got)
	}
}

func TestUnparseableWidgetIsSkippedNotFatal(t *testing.T) {
	got := loadWidgets(widgetTree(map[string]string{
		"broken": `{ this is not json`,
		"fine":   `{"id":"fine","name":"Fine","slots":["left"]}`,
	}))
	if len(got) != 1 || got[0].ID != "fine" {
		t.Fatalf("got %v, want the one good widget: a broken extra must not take the registry with it", got)
	}
}

// An unknown dock is dropped from the list and the widget is kept, because a
// widget listing one slot this build does not have and one it does is still
// placeable in the one it does. A widget left with no slot at all is dropped:
// nothing could ever place it, and keeping it would put a row in the registry
// that is an invitation to a placement that always fails.
func TestUnknownSlotIsDroppedAndAnEmptyListSkipsTheWidget(t *testing.T) {
	got := loadWidgets(widgetTree(map[string]string{
		"half": `{"id":"half","name":"Half","slots":["sidebar","left"]}`,
		"none": `{"id":"none","name":"None","slots":["sidebar"]}`,
	}))
	if len(got) != 1 || got[0].ID != "half" {
		t.Fatalf("got %v, want only the widget with a real slot left", got)
	}
	if len(got[0].Slots) != 1 || got[0].Slots[0] != "left" {
		t.Errorf("slots = %v, want just the one this build has", got[0].Slots)
	}
}

// A placement aimed at a slot that is not a dock cannot become a card however
// the registry turns out, so themes.go drops it while reading the folder.
func TestThemeLayoutDropsAnUnknownSlot(t *testing.T) {
	tree := fstest.MapFS{
		themesDir + "/t/theme.json": {Data: []byte(`{"id":"t","name":"T","ground":"any","layout":[
			{"widget":"wire","slot":"left"},
			{"widget":"wire","slot":"middle"},
			{"widget":"","slot":"left"}
		]}`)},
		themesDir + "/t/theme.css": {Data: []byte("")},
	}
	got := loadThemes(tree)
	if len(got) != 1 {
		t.Fatalf("got %v, want the theme kept", got)
	}
	if len(got[0].Layout) != 1 || got[0].Layout[0].Slot != "left" {
		t.Fatalf("layout = %v, want only the placement aimed at a real dock", got[0].Layout)
	}
}

// The other half of the same question: the slot is real, but the widget is not
// embedded or does not fit the dock that was asked for.
func TestResolvePlacementsDropsWhatCannotBeBuilt(t *testing.T) {
	widgets := []Widget{{ID: "tape", Name: "Tape", Slots: []string{"left", "right"}}}
	themes := []Theme{{ID: "t", Name: "T", Layout: []Placement{
		{Widget: "tape", Slot: "left"},
		{Widget: "tape", Slot: "top"},   // real widget, wrong dock
		{Widget: "ghost", Slot: "left"}, // not embedded
	}}}

	got := resolvePlacements(themes, widgets)
	if len(got) != 1 {
		t.Fatalf("got %d themes, want 1", len(got))
	}
	if len(got[0].Layout) != 1 {
		t.Fatalf("layout = %v, want only the placement that can be built", got[0].Layout)
	}
	if got[0].Layout[0].Slot != "left" {
		t.Errorf("kept %q, want the left one", got[0].Layout[0].Slot)
	}

	// The themes it was handed are not modified, so a caller that kept a
	// reference to the unpruned list still has one.
	if len(themes[0].Layout) != 3 {
		t.Errorf("the input theme was mutated: layout is now %v", themes[0].Layout)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// widgetTree builds a registry from id -> widget.json, with the two required
// files present so the only thing under test is the manifest.
func widgetTree(manifests map[string]string) fstest.MapFS {
	tree := fstest.MapFS{}
	for dir, json := range manifests {
		tree[widgetsDir+"/"+dir+"/widget.json"] = &fstest.MapFile{Data: []byte(json)}
		tree[widgetsDir+"/"+dir+"/widget.js"] = &fstest.MapFile{Data: []byte("")}
		tree[widgetsDir+"/"+dir+"/widget.css"] = &fstest.MapFile{Data: []byte("")}
	}
	return tree
}

// selectors returns every selector in a stylesheet: the text before each
// opening brace, split on commas and trimmed.
//
// At-rules are skipped rather than checked — `@media (max-width: 600px)` is
// not a selector and the selectors inside it are returned on their own, which
// is what the caller wants to look at. Declarations are skipped by taking only
// the text after the last `;` or `}`, which is where a selector starts.
func selectors(css string) []string {
	var out []string
	rest := stripCSSComments(css)

	for {
		open := strings.Index(rest, "{")
		if open < 0 {
			return out
		}
		head := rest[:open]
		rest = rest[open+1:]

		if cut := strings.LastIndexAny(head, ";}"); cut >= 0 {
			head = head[cut+1:]
		}
		for _, sel := range strings.Split(head, ",") {
			sel = strings.TrimSpace(sel)
			if sel == "" || strings.HasPrefix(sel, "@") {
				continue
			}
			out = append(out, sel)
		}
	}
}

func stripCSSComments(s string) string {
	var b strings.Builder
	for {
		start := strings.Index(s, "/*")
		if start < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:start])
		end := strings.Index(s[start+2:], "*/")
		if end < 0 {
			return b.String()
		}
		s = s[start+2+end+2:]
	}
}
