// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// The UI is //go:embed-ed, so the server knows the exact bytes of every asset
// at build time and can say so. Without that, style.css and app.js went out
// with no Cache-Control, no ETag and no Last-Modified — embed.FS reports a zero
// modtime, so net/http had nothing to put there — and a browser handed a
// response with no freshness information at all is free to invent one. The loop
// this lab is built around is edit, `docker compose up -d --build --no-deps
// control`, look at the page; a rebuilt server that does not change the page
// reads as a broken fix, and that cost a session on #68.
//
// So every asset carries an ETag over its own bytes and Cache-Control:
// no-cache, which does not mean "do not store" — it means store it and ask
// before using it. The browser revalidates on every load and gets a 304 with no
// body back when nothing moved. One round trip against a server on loopback,
// and the page can never be a new app.js against yesterday's style.css.
//
// The hash is computed once at startup rather than per request: the bytes are
// in the binary and cannot change while it runs.

// staticUI serves fsys with a per-file ETag and Cache-Control: no-cache.
//
// It sets the header and then hands off to http.FileServer, which is not a
// trick: http.ServeContent reads the ETag already on the ResponseWriter when it
// evaluates If-None-Match, so the 304 handling, range requests and content
// sniffing all stay where they were.
func staticUI(fsys fs.FS) (http.Handler, error) {
	tags, err := assetETags(fsys)
	if err != nil {
		return nil, err
	}
	files := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tag, ok := tags[assetName(r.URL.Path)]; ok {
			w.Header().Set("ETag", tag)
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	}), nil
}

// assetETags hashes every file in fsys, keyed by its path within fsys.
func assetETags(fsys fs.FS) (map[string]string, error) {
	tags := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		// Half of SHA-256 is far more than enough to tell two versions of one
		// stylesheet apart, and a shorter header is easier to read in curl -I.
		tags[p] = `"` + hex.EncodeToString(sum[:16]) + `"`
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tags, nil
}

// assetName maps a request path to the name of the embedded file
// http.FileServer will serve for it, so the two agree on what is being tagged.
// A directory gets its index.html, which is how / becomes index.html.
func assetName(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// Before Clean, which strips the trailing slash that marks a directory.
	if strings.HasSuffix(p, "/") {
		p += "index.html"
	}
	return strings.TrimPrefix(path.Clean(p), "/")
}
