// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func testUI() fs.FS {
	return fstest.MapFS{
		"index.html":   {Data: []byte("<!doctype html><link rel=stylesheet href=style.css>")},
		"style.css":    {Data: []byte(".panel { color: red }")},
		"app.js":       {Data: []byte("export const x = 1\n")},
		"hud/scene.js": {Data: []byte("export function scene() {}\n")},
	}
}

func serveUI(t *testing.T, fsys fs.FS) http.Handler {
	t.Helper()
	h, err := staticUI(fsys)
	if err != nil {
		t.Fatalf("staticUI: %v", err)
	}
	return h
}

func get(t *testing.T, h http.Handler, path string, headers map[string]string) *http.Response {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result()
}

// Every asset answers with something the browser can revalidate against. This
// is the whole bug in #70: with no ETag and no Cache-Control, a rebuilt server
// does not change what the reader sees.
func TestAssetsCarryAnETagAndRevalidate(t *testing.T) {
	h := serveUI(t, testUI())

	// Not /index.html: http.FileServer redirects that to / on its own, and
	// that predates this change.
	for _, path := range []string{"/", "/style.css", "/app.js", "/hud/scene.js"} {
		res := get(t, h, path, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d, want 200", path, res.StatusCode)
		}
		if got := res.Header.Get("ETag"); got == "" {
			t.Errorf("%s: no ETag", path)
		}
		if got := res.Header.Get("Cache-Control"); got != "no-cache" {
			t.Errorf("%s: Cache-Control %q, want %q", path, got, "no-cache")
		}
	}
}

// The cheap half: an unchanged asset comes back as a bodiless 304, so
// revalidating on every load costs a round trip and not a stylesheet.
func TestUnchangedAssetIsNotModified(t *testing.T) {
	h := serveUI(t, testUI())

	first := get(t, h, "/style.css", nil)
	tag := first.Header.Get("ETag")
	if tag == "" {
		t.Fatal("no ETag on the first response")
	}

	second := get(t, h, "/style.css", map[string]string{"If-None-Match": tag})
	if second.StatusCode != http.StatusNotModified {
		t.Fatalf("status %d, want 304", second.StatusCode)
	}
	if n := second.ContentLength; n > 0 {
		t.Errorf("304 carried %d bytes of body", n)
	}
	if got := second.Header.Get("ETag"); got != tag {
		t.Errorf("304 ETag %q, want %q", got, tag)
	}
}

// The point of hashing the bytes rather than stamping a build: edit the file,
// and the tag the browser is holding stops matching.
func TestEditedAssetGetsANewETag(t *testing.T) {
	before := get(t, serveUI(t, testUI()), "/style.css", nil).Header.Get("ETag")

	edited := testUI().(fstest.MapFS)
	edited["style.css"] = &fstest.MapFile{Data: []byte(".panel { color: blue }")}
	after := get(t, serveUI(t, edited), "/style.css", nil).Header.Get("ETag")

	if before == "" || after == "" {
		t.Fatalf("missing ETag: before %q, after %q", before, after)
	}
	if before == after {
		t.Errorf("ETag %q survived an edit to the file", before)
	}

	// And the stale tag no longer satisfies the request, so the browser is
	// handed the new bytes rather than told to keep the old ones.
	res := get(t, serveUI(t, edited), "/style.css", map[string]string{"If-None-Match": before})
	if res.StatusCode != http.StatusOK {
		t.Errorf("status %d for a stale ETag, want 200", res.StatusCode)
	}
}

// Two assets that differ must not share a tag, or a page can be a new app.js
// against an old style.css with nothing indicating it.
func TestETagsAreNotSharedBetweenAssets(t *testing.T) {
	h := serveUI(t, testUI())

	seen := map[string]string{}
	for _, path := range []string{"/", "/style.css", "/app.js", "/hud/scene.js"} {
		tag := get(t, h, path, nil).Header.Get("ETag")
		if other, clash := seen[tag]; clash {
			t.Errorf("%s and %s share the ETag %s", other, path, tag)
		}
		seen[tag] = path
	}
}

// The tag on / has to be the tag of index.html, the file / actually serves, or
// the root document is the one page that never revalidates correctly.
func TestRootIsTaggedWithIndexHTML(t *testing.T) {
	fsys := testUI()
	tags, err := assetETags(fsys)
	if err != nil {
		t.Fatalf("assetETags: %v", err)
	}

	root := get(t, serveUI(t, fsys), "/", nil).Header.Get("ETag")
	if root != tags["index.html"] {
		t.Errorf("/ tagged %q, index.html hashes to %q", root, tags["index.html"])
	}
}

func TestAssetName(t *testing.T) {
	cases := map[string]string{
		"/":               "index.html",
		"/index.html":     "index.html",
		"/style.css":      "style.css",
		"/hud/":           "hud/index.html",
		"/hud/scene.js":   "hud/scene.js",
		"/./style.css":    "style.css",
		"/hud/../app.js":  "app.js",
		"/../../etc/pass": "etc/pass",
		"style.css":       "style.css",
	}
	for in, want := range cases {
		if got := assetName(in); got != want {
			t.Errorf("assetName(%q) = %q, want %q", in, got, want)
		}
	}
}

// A path with no file behind it is served exactly as it was before: no tag
// invented for something that does not exist, and net/http still 404s.
func TestMissingAssetIsUntagged(t *testing.T) {
	res := get(t, serveUI(t, testUI()), "/nope.css", nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", res.StatusCode)
	}
	if got := res.Header.Get("ETag"); got != "" {
		t.Errorf("404 carried ETag %q", got)
	}
}

// The real embedded UI, not a fixture: the files this lab actually ships are
// the ones that were going out unrevalidatable.
func TestEmbeddedUIIsTagged(t *testing.T) {
	ui, err := fs.Sub(uiFS, "ui")
	if err != nil {
		t.Fatalf("embedded UI: %v", err)
	}
	h := serveUI(t, ui)

	for _, path := range []string{"/", "/style.css", "/app.js"} {
		res := get(t, h, path, nil)
		if res.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d, want 200", path, res.StatusCode)
		}
		if res.Header.Get("ETag") == "" || res.Header.Get("Cache-Control") != "no-cache" {
			t.Errorf("%s: ETag %q, Cache-Control %q",
				path, res.Header.Get("ETag"), res.Header.Get("Cache-Control"))
		}
	}
}
