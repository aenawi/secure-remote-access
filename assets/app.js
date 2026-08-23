/* ============================================================
   Shared behaviour: theme, sidebar, TOC, search, copy buttons,
   and persistent checklists. Everything degrades gracefully and
   works from file:// with no server.
   ============================================================ */
(function () {
  "use strict";

  var PAGE = document.body.dataset.page || "index";
  var DEPTH = document.body.dataset.depth === "1" ? "../" : "";
  var LS = {
    theme: "srdg:theme",
    check: "srdg:checks"
  };

  /* ---------- theme ---------- */
  function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem(LS.theme); } catch (e) {}
    if (saved === "dark" || saved === "light") {
      document.documentElement.setAttribute("data-theme", saved);
    }
    var btn = document.createElement("button");
    btn.className = "theme-toggle";
    btn.type = "button";
    btn.setAttribute("aria-label", "Toggle colour theme");
    function icon() {
      var cur = document.documentElement.getAttribute("data-theme");
      var dark = cur === "dark" || (!cur && window.matchMedia("(prefers-color-scheme: dark)").matches);
      btn.textContent = dark ? "☀" : "☽";
    }
    btn.addEventListener("click", function () {
      var cur = document.documentElement.getAttribute("data-theme");
      var dark = cur === "dark" || (!cur && window.matchMedia("(prefers-color-scheme: dark)").matches);
      var next = dark ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem(LS.theme, next); } catch (e) {}
      icon();
    });
    icon();
    document.body.appendChild(btn);
  }

  /* ---------- sidebar ---------- */
  function buildSidebar() {
    var host = document.querySelector(".sidebar");
    if (!host || !window.GUIDE_NAV) return;

    var html = '' +
      '<div class="brand"><a href="' + DEPTH + 'index.html">' +
        '<span class="mark">' +
          '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">' +
            '<path d="M12 2.5 4 6v6c0 4.6 3.2 8.5 8 9.5 4.8-1 8-4.9 8-9.5V6l-8-3.5Z" ' +
              'stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>' +
            '<path d="M8.6 12.2 11 14.6l4.6-4.8" stroke="currentColor" stroke-width="1.8" ' +
              'stroke-linecap="round" stroke-linejoin="round"/>' +
          '</svg>Secure Remote Access</span>' +
        '<span class="sub">VPS &middot; Laptops &middot; Phones, joined by one tailnet</span>' +
      '</a></div>' +
      '<div class="nav-search"><input type="search" id="navq" placeholder="Filter chapters…" ' +
        'autocomplete="off" spellcheck="false" aria-label="Filter chapters"></div>' +
      '<nav class="nav" id="navlist">';

    window.GUIDE_NAV.forEach(function (g) {
      html += '<div class="nav-group">' + g.group + "</div>";
      g.items.forEach(function (it) {
        html += '<a href="' + DEPTH + it.file + '" data-id="' + it.id + '" ' +
                'data-search="' + (it.title + " " + it.desc).toLowerCase().replace(/"/g, "") + '">' +
                '<span class="num">' + it.n + "</span><span>" + it.title + "</span></a>";
      });
    });
    html += "</nav>";
    host.innerHTML = html;

    var active = host.querySelector('a[data-id="' + PAGE + '"]');
    if (active) {
      active.classList.add("active");
      active.setAttribute("aria-current", "page");
    }

    var q = document.getElementById("navq");
    q.addEventListener("input", function () {
      var term = q.value.trim().toLowerCase();
      host.querySelectorAll(".nav a").forEach(function (a) {
        a.classList.toggle("hidden", term && a.dataset.search.indexOf(term) === -1);
      });
      host.querySelectorAll(".nav-group").forEach(function (grp) {
        var any = false, el = grp.nextElementSibling;
        while (el && el.tagName === "A") {
          if (!el.classList.contains("hidden")) any = true;
          el = el.nextElementSibling;
        }
        grp.style.display = any ? "" : "none";
      });
    });
  }

  /* ---------- mobile drawer ---------- */
  function initDrawer() {
    var side = document.querySelector(".sidebar");
    if (!side) return;
    var bar = document.createElement("div");
    bar.className = "topbar";
    var cur = (window.GUIDE_FLAT || []).filter(function (i) { return i.id === PAGE; })[0];
    bar.innerHTML = '<button type="button" aria-label="Open navigation">☰</button>' +
                    '<span class="tt">' + (cur ? cur.n + " · " + cur.title : "Secure Remote Access") + "</span>";
    document.body.insertBefore(bar, document.body.firstChild);

    var scrim = document.createElement("div");
    scrim.className = "scrim";
    document.body.appendChild(scrim);

    function close() { side.classList.remove("open"); scrim.classList.remove("show"); }
    bar.querySelector("button").addEventListener("click", function () {
      side.classList.toggle("open");
      scrim.classList.toggle("show");
    });
    scrim.addEventListener("click", close);
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") close(); });
  }

  /* ---------- table of contents ---------- */
  function buildToc() {
    var toc = document.querySelector(".toc");
    var content = document.querySelector(".content");
    if (!toc || !content) return;
    var heads = content.querySelectorAll("h2, h3");
    if (heads.length < 2) { toc.style.display = "none"; return; }

    var html = "<h4>On this page</h4>";
    heads.forEach(function (h, i) {
      if (!h.id) h.id = "s" + i + "-" + (h.textContent || "").toLowerCase()
        .replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40);
      html += '<a href="#' + h.id + '" class="' + (h.tagName === "H3" ? "lvl3" : "") + '">' +
              h.textContent + "</a>";
    });
    toc.innerHTML = html;

    var links = toc.querySelectorAll("a");
    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        links.forEach(function (l) {
          l.classList.toggle("active", l.getAttribute("href") === "#" + en.target.id);
        });
      });
    }, { rootMargin: "-80px 0px -70% 0px" });
    heads.forEach(function (h) { obs.observe(h); });
  }

  /* ---------- copy buttons ---------- */
  function initCopy() {
    document.querySelectorAll("pre").forEach(function (pre) {
      if (pre.parentElement.classList.contains("code-wrap")) return;
      var wrap = document.createElement("div");
      wrap.className = "code-wrap";
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(pre);

      var btn = document.createElement("button");
      btn.className = "copy-btn";
      btn.type = "button";
      btn.textContent = "Copy";
      btn.addEventListener("click", function () {
        var text = pre.innerText;
        function done() {
          btn.textContent = "Copied";
          btn.classList.add("done");
          setTimeout(function () { btn.textContent = "Copy"; btn.classList.remove("done"); }, 1400);
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, fallback);
        } else { fallback(); }
        function fallback() {
          var ta = document.createElement("textarea");
          ta.value = text;
          ta.style.position = "fixed";
          ta.style.opacity = "0";
          document.body.appendChild(ta);
          ta.select();
          try { document.execCommand("copy"); done(); } catch (e) {}
          document.body.removeChild(ta);
        }
      });
      wrap.appendChild(btn);
    });
  }

  /* ---------- persistent checklists ---------- */
  function initChecklists() {
    var lists = document.querySelectorAll(".checklist");
    if (!lists.length) return;

    var state = {};
    try { state = JSON.parse(localStorage.getItem(LS.check) || "{}"); } catch (e) { state = {}; }

    function save() { try { localStorage.setItem(LS.check, JSON.stringify(state)); } catch (e) {} }

    var all = [];
    lists.forEach(function (list, li) {
      list.querySelectorAll("li").forEach(function (item, ii) {
        var key = PAGE + ":" + li + ":" + ii;
        var cb = document.createElement("input");
        cb.type = "checkbox";
        cb.id = "cb-" + key.replace(/:/g, "-");
        var label = document.createElement("label");
        label.setAttribute("for", cb.id);
        label.innerHTML = item.innerHTML;
        item.innerHTML = "";
        item.appendChild(cb);
        item.appendChild(label);

        if (state[key]) { cb.checked = true; item.classList.add("done"); }
        cb.addEventListener("change", function () {
          state[key] = cb.checked;
          item.classList.toggle("done", cb.checked);
          save();
          paint();
        });
        all.push(cb);
      });
    });

    var bar = document.querySelector(".progress-bar > span");
    var lab = document.querySelector(".progress-label");
    function paint() {
      if (!all.length) return;
      var n = all.filter(function (c) { return c.checked; }).length;
      var pct = Math.round((n / all.length) * 100);
      if (bar) bar.style.width = pct + "%";
      if (lab) lab.textContent = n + " / " + all.length + " complete · " + pct + "%";
    }
    paint();

    var reset = document.querySelector("[data-reset-checks]");
    if (reset) {
      reset.addEventListener("click", function () {
        all.forEach(function (c) {
          c.checked = false;
          c.closest("li").classList.remove("done");
        });
        Object.keys(state).forEach(function (k) {
          if (k.indexOf(PAGE + ":") === 0) delete state[k];
        });
        save();
        paint();
      });
    }
  }

  /* ---------- prev / next ---------- */
  function buildPager() {
    var host = document.querySelector(".pager");
    if (!host || !window.GUIDE_FLAT) return;
    var flat = window.GUIDE_FLAT;
    var i = flat.findIndex(function (x) { return x.id === PAGE; });
    if (i === -1) return;
    var prev = flat[i - 1], next = flat[i + 1], html = "";
    if (prev) html += '<a class="prev" href="' + DEPTH + prev.file + '">' +
      '<div class="dir">← Previous</div><div class="ttl">' + prev.title + "</div></a>";
    if (next) html += '<a class="next" href="' + DEPTH + next.file + '">' +
      '<div class="dir">Next →</div><div class="ttl">' + next.title + "</div></a>";
    host.innerHTML = html;
  }

  /* ---------- go ---------- */
  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }
  ready(function () {
    initTheme();
    buildSidebar();
    initDrawer();
    buildToc();
    initCopy();
    initChecklists();
    buildPager();
  });
})();
