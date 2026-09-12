// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

// The store is read off the embedded UI, so these run against the real
// folders rather than a fixture wherever the question is "is what shipped
// well-formed". A theme added with a typo in its id, or without the
// stylesheet the page will ask for, is exactly the failure this catches — and
// it is silent in a browser, because a stylesheet that 404s leaves the board
// painting the palette it already had.

func embeddedUI(t *testing.T) fs.FS {
	t.Helper()
	ui, err := fs.Sub(uiFS, "ui")
	if err != nil {
		t.Fatalf("embedded UI: %v", err)
	}
	return ui
}

func TestEmbeddedThemesAreWellFormed(t *testing.T) {
	got := loadThemes(embeddedUI(t))
	if len(got) == 0 {
		t.Fatal("no themes were embedded; ui/hud/themes should hold at least " + baseTheme)
	}

	seen := map[string]bool{}
	for _, th := range got {
		if seen[th.ID] {
			t.Errorf("theme %q appears twice", th.ID)
		}
		seen[th.ID] = true

		if th.Name == "" {
			t.Errorf("theme %q has no name, so the picker would show an empty row", th.ID)
		}
		if !validGrounds[th.Ground] {
			t.Errorf("theme %q has ground %q, want light, dark or any", th.ID, th.Ground)
		}
		// The note is what the picker puts in its title attribute. A theme
		// with none is not broken, but it is the one thing a reader browsing
		// the store has to go on.
		if th.Note == "" {
			t.Errorf("theme %q has no note", th.ID)
		}
	}

	if !seen[baseTheme] {
		t.Errorf("%q was not found; it is the fallback and has to exist", baseTheme)
	}
}

// The base theme is the one that must override nothing: it is what the board
// looked like before the store, and it is where a saved id falls back to. A
// stylesheet with declarations in it would make "chapter" a palette of its own
// and quietly fork the nine colours away from style.css.
func TestBaseThemeOverridesNothing(t *testing.T) {
	b, err := fs.ReadFile(embeddedUI(t), themesDir+"/"+baseTheme+"/theme.css")
	if err != nil {
		t.Fatalf("reading the base theme: %v", err)
	}
	if stripComments(string(b)) != "" {
		t.Errorf("%s/theme.css declares something; it is meant to override nothing:\n%s",
			baseTheme, stripComments(string(b)))
	}
}

// stripComments answers one question about a stylesheet: does it set anything?
// It strips /* ... */ and then looks for a colon inside a block, which is what
// a declaration is and what a selector's pseudo-class is not — :root carries a
// colon too, and it is outside the braces.
//
// It returns the offending text rather than a bool so the failure message can
// show what was found. Empty means the sheet declares nothing.
func stripComments(s string) string {
	var out []rune
	in := []rune(s)
	for i := 0; i < len(in); i++ {
		if i+1 < len(in) && in[i] == '/' && in[i+1] == '*' {
			for i += 2; i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/'); i++ {
			}
			i++
			continue
		}
		out = append(out, in[i])
	}

	depth, start := 0, -1
	for i, r := range out {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
		case ':':
			if depth > 0 && start < 0 {
				start = i
			}
		}
	}
	if start < 0 {
		return ""
	}
	return string(out[start:min(start+60, len(out))])
}

// A folder whose json disagrees with it would have the page load one
// stylesheet and select a different attribute value, which is a board that
// keeps its old colours and says nothing. Checked against a synthetic tree
// because the embedded one is — and should stay — correct.
func TestThemeIDMustMatchItsFolder(t *testing.T) {
	tree := fstest.MapFS{
		themesDir + "/good/theme.json": {Data: []byte(`{"id":"good","name":"Good","ground":"dark"}`)},
		themesDir + "/good/theme.css":  {Data: []byte("")},
		themesDir + "/liar/theme.json": {Data: []byte(`{"id":"somethingelse","name":"Liar","ground":"dark"}`)},
		themesDir + "/liar/theme.css":  {Data: []byte("")},
	}
	got := loadThemes(tree)
	if len(got) != 1 || got[0].ID != "good" {
		t.Fatalf("got %v, want only the folder whose id matches it", got)
	}
}

func TestThemeWithoutStylesheetIsSkipped(t *testing.T) {
	tree := fstest.MapFS{
		themesDir + "/nocss/theme.json": {Data: []byte(`{"id":"nocss","name":"No CSS","ground":"any"}`)},
	}
	if got := loadThemes(tree); len(got) != 0 {
		t.Fatalf("got %v, want nothing: the page would ask for a theme.css that is not there", got)
	}
}

func TestUnparseableThemeIsSkippedNotFatal(t *testing.T) {
	tree := fstest.MapFS{
		themesDir + "/broken/theme.json": {Data: []byte(`{ this is not json`)},
		themesDir + "/broken/theme.css":  {Data: []byte("")},
		themesDir + "/fine/theme.json":   {Data: []byte(`{"id":"fine","name":"Fine","ground":"any"}`)},
		themesDir + "/fine/theme.css":    {Data: []byte("")},
	}
	got := loadThemes(tree)
	if len(got) != 1 || got[0].ID != "fine" {
		t.Fatalf("got %v, want the one good theme: a broken extra must not take the store with it", got)
	}
}

// An unrecognised ground is read as "any" rather than dropping the theme.
// Selecting it then leaves the page's own light/dark setting alone, which is
// the harmless reading.
func TestUnknownGroundIsReadAsAny(t *testing.T) {
	tree := fstest.MapFS{
		themesDir + "/odd/theme.json": {Data: []byte(`{"id":"odd","name":"Odd","ground":"chartreuse"}`)},
		themesDir + "/odd/theme.css":  {Data: []byte("")},
	}
	got := loadThemes(tree)
	if len(got) != 1 {
		t.Fatalf("got %v, want the theme kept", got)
	}
	if got[0].Ground != "any" {
		t.Errorf("ground = %q, want any", got[0].Ground)
	}
}

// The base theme sorts first because it is the one a reader falls back to and
// the one the picker opens on; the rest are alphabetical by the name shown,
// not by the id, which is what somebody scanning the list is reading.
func TestBaseThemeSortsFirst(t *testing.T) {
	tree := fstest.MapFS{
		themesDir + "/aaa/theme.json":               {Data: []byte(`{"id":"aaa","name":"Aaa","ground":"any"}`)},
		themesDir + "/aaa/theme.css":                {Data: []byte("")},
		themesDir + "/" + baseTheme + "/theme.json": {Data: []byte(`{"id":"` + baseTheme + `","name":"Zzz","ground":"any"}`)},
		themesDir + "/" + baseTheme + "/theme.css":  {Data: []byte("")},
	}
	got := loadThemes(tree)
	if len(got) != 2 {
		t.Fatalf("got %v, want two", got)
	}
	if got[0].ID != baseTheme {
		t.Errorf("first = %q, want %q even though its name sorts last", got[0].ID, baseTheme)
	}
}
