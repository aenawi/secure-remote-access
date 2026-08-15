/* ------------------------------------------------------------------
   anim.js — tiny SVG simulation engine for the guide's diagrams.

   Progressive enhancement: with JS off, every layer of the diagram is
   visible at once and it reads as the static figure it always was.
   With JS on, the figure gains a timeline, scenario switches and
   animated packets.

   HTML contract
   -------------
   <figure class="diagram sim" data-sim data-step-ms="3400">
     <div class="sim-bar">                     scenario buttons
       <button data-scenario="home" ...>
     </div>
     <svg data-step="0"> ... </svg>
     <div class="sim-controls"> ... </div>     prev / play / next
     <ol class="sim-steps"> <li data-at="1"> narration </li> ... </ol>
   </figure>

   Attributes understood on any element (inside or outside the svg)
   ---------------------------------------------------------------
     data-at="2"      visible only on step 2
     data-at="2+"     visible from step 2 onward
     data-at="1-3"    visible on steps 1 through 3
     data-scn="a b"   additionally requires the active scenario to be a or b
     data-flow        this <path> carries animated packets while visible
     data-flow-rev    packets travel end -> start instead
     data-speed="0.2" packet speed in px/ms (default 0.22)
     data-count="3"   packets in flight on this path (default 2)
   ------------------------------------------------------------------ */
(function () {
  'use strict';

  var SVG_NS = 'http://www.w3.org/2000/svg';
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)');

  /* ---- data-at parsing ------------------------------------------- */
  function range(spec) {
    if (!spec) return null;
    spec = spec.trim();
    if (/^\d+\+$/.test(spec)) return [parseInt(spec, 10), Infinity];
    var m = spec.match(/^(\d+)\s*-\s*(\d+)$/);
    if (m) return [+m[1], +m[2]];
    var n = parseInt(spec, 10);
    return isNaN(n) ? null : [n, n];
  }

  function Sim(fig) {
    this.fig = fig;
    this.svg = fig.querySelector('svg');
    if (!this.svg) return;

    this.stepMs = parseInt(fig.getAttribute('data-step-ms'), 10) || 3400;
    this.step = 0;
    this.playing = false;
    this.touched = false;
    this.raf = null;
    this.lastFrame = 0;
    this.stepElapsed = 0;

    this.layers = [];
    var self = this;
    Array.prototype.forEach.call(fig.querySelectorAll('[data-at]'), function (el) {
      var r = range(el.getAttribute('data-at'));
      if (!r) return;
      var scn = (el.getAttribute('data-scn') || '').trim();
      self.layers.push({
        el: el,
        from: r[0],
        to: r[1],
        scn: scn ? scn.split(/\s+/) : null
      });
    });

    this.maxStep = this.layers.reduce(function (m, l) {
      return Math.max(m, l.to === Infinity ? l.from : l.to);
    }, 0);

    /* scenario buttons */
    this.scnButtons = Array.prototype.slice.call(
      fig.querySelectorAll('[data-scenario]')
    );
    this.scenario = this.scnButtons.length
      ? this.scnButtons[0].getAttribute('data-scenario')
      : '';

    /* packet layer sits above everything already in the svg */
    this.packetLayer = document.createElementNS(SVG_NS, 'g');
    this.packetLayer.setAttribute('class', 'sim-packets');
    this.packetLayer.setAttribute('aria-hidden', 'true');
    this.svg.appendChild(this.packetLayer);
    this.packets = [];

    this.wire();
    this.fig.classList.add('sim-on');
    this.goto(0);

    /* autoplay once the figure actually scrolls into view */
    if (!reduced.matches && 'IntersectionObserver' in window) {
      var seen = false;
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
          /* autoplay once, and never over the top of someone who has
             already taken control of the timeline */
          if (e.isIntersecting && !seen && !self.touched) {
            seen = true;
            self.play();
          } else if (!e.isIntersecting && self.playing) {
            self.pause();
          }
        });
      }, { threshold: 0.35 });
      io.observe(fig);
    }
  }

  Sim.prototype.wire = function () {
    var self = this;

    this.fig.addEventListener('click', function (ev) {
      var btn = ev.target.closest('button');
      if (!btn || !self.fig.contains(btn)) return;
      self.touched = true;

      var act = btn.getAttribute('data-act');
      if (act === 'play') { self.playing ? self.pause() : self.play(); return; }
      if (act === 'next') { self.pause(); self.goto(self.step + 1); return; }
      if (act === 'prev') { self.pause(); self.goto(self.step - 1); return; }
      if (act === 'restart') { self.goto(0); self.play(); return; }

      var to = btn.getAttribute('data-goto');
      if (to !== null) { self.pause(); self.goto(parseInt(to, 10)); return; }

      var scn = btn.getAttribute('data-scenario');
      if (scn) { self.setScenario(scn); }
    });

    /* left / right arrows step the timeline when the figure has focus */
    this.fig.addEventListener('keydown', function (ev) {
      if (['ArrowRight', 'ArrowLeft', ' '].indexOf(ev.key) !== -1) self.touched = true;
      if (ev.key === 'ArrowRight') { self.pause(); self.goto(self.step + 1); ev.preventDefault(); }
      else if (ev.key === 'ArrowLeft') { self.pause(); self.goto(self.step - 1); ev.preventDefault(); }
      else if (ev.key === ' ' && ev.target === self.fig) {
        self.playing ? self.pause() : self.play();
        ev.preventDefault();
      }
    });

    reduced.addEventListener('change', function () {
      if (reduced.matches) self.pause();
    });
  };

  Sim.prototype.setScenario = function (name) {
    this.scenario = name;
    this.scnButtons.forEach(function (b) {
      var on = b.getAttribute('data-scenario') === name;
      b.classList.toggle('is-on', on);
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
    this.goto(this.step);
    if (!reduced.matches && !this.playing) this.play();
  };

  Sim.prototype.visible = function (l) {
    if (this.step < l.from || this.step > l.to) return false;
    if (l.scn && l.scn.indexOf(this.scenario) === -1) return false;
    return true;
  };

  Sim.prototype.goto = function (n) {
    if (n > this.maxStep) n = 0;
    if (n < 0) n = this.maxStep;
    this.step = n;
    this.stepElapsed = 0;
    this.svg.setAttribute('data-step', String(n));
    this.fig.setAttribute('data-step', String(n));

    var self = this;
    this.layers.forEach(function (l) {
      l.el.classList.toggle('is-on', self.visible(l));
    });

    /* timeline dots */
    Array.prototype.forEach.call(this.fig.querySelectorAll('[data-goto]'), function (d) {
      var on = parseInt(d.getAttribute('data-goto'), 10) === n;
      d.classList.toggle('is-on', on);
      d.setAttribute('aria-current', on ? 'step' : 'false');
    });

    this.buildPackets();
  };

  /* ---- packets ---------------------------------------------------- */
  Sim.prototype.buildPackets = function () {
    while (this.packetLayer.firstChild) {
      this.packetLayer.removeChild(this.packetLayer.firstChild);
    }
    this.packets = [];
    if (reduced.matches) return;

    var self = this;
    var flows = this.svg.querySelectorAll('[data-flow]');

    Array.prototype.forEach.call(flows, function (path) {
      /* A flow only runs while the layer that owns it is on. The owner is
         the path itself if it carries data-at, else its nearest ancestor
         that does — goto() has already resolved .is-on for both. */
      var host = path.closest ? path.closest('[data-at]') : null;
      if (!host || !host.classList.contains('is-on')) return;

      var len = 0;
      try { len = path.getTotalLength(); } catch (e) { return; }
      if (!len) return;

      var count = parseInt(path.getAttribute('data-count'), 10) || 2;
      var speed = parseFloat(path.getAttribute('data-speed')) || 0.22;
      var rev = path.hasAttribute('data-flow-rev');
      var cls = path.getAttribute('data-flow') || 'accent';

      for (var i = 0; i < count; i++) {
        var dot = document.createElementNS(SVG_NS, 'circle');
        dot.setAttribute('r', path.getAttribute('data-r') || '4');
        dot.setAttribute('class', 'sim-packet sim-packet-' + cls);
        self.packetLayer.appendChild(dot);
        self.packets.push({
          el: dot,
          path: path,
          len: len,
          speed: speed,
          rev: rev,
          t: (i / count) * len
        });
      }
    });

    this.drawPackets();
  };

  Sim.prototype.drawPackets = function () {
    for (var i = 0; i < this.packets.length; i++) {
      var p = this.packets[i];
      var d = p.rev ? p.len - p.t : p.t;
      var pt = p.path.getPointAtLength(d);
      p.el.setAttribute('cx', pt.x);
      p.el.setAttribute('cy', pt.y);
      /* fade in at the head of the path, out at the tail */
      var edge = Math.min(p.t, p.len - p.t) / Math.min(40, p.len / 2);
      p.el.setAttribute('opacity', Math.max(0, Math.min(1, edge)).toFixed(2));
    }
  };

  /* ---- transport -------------------------------------------------- */
  Sim.prototype.play = function () {
    if (this.playing || reduced.matches) return;
    this.playing = true;
    this.fig.classList.add('is-playing');
    this.setPlayLabel('Pause', '❚❚');
    this.lastFrame = 0;
    var self = this;
    this.raf = requestAnimationFrame(function (t) { self.frame(t); });
  };

  Sim.prototype.pause = function () {
    this.playing = false;
    this.fig.classList.remove('is-playing');
    this.setPlayLabel('Play', '▶');
    if (this.raf) cancelAnimationFrame(this.raf);
    this.raf = null;
  };

  Sim.prototype.setPlayLabel = function (label, glyph) {
    var btn = this.fig.querySelector('[data-act="play"]');
    if (!btn) return;
    btn.setAttribute('aria-label', label);
    var g = btn.querySelector('.sim-glyph');
    if (g) g.textContent = glyph;
    var t = btn.querySelector('.sim-btn-text');
    if (t) t.textContent = label;
  };

  Sim.prototype.frame = function (now) {
    if (!this.playing) return;
    var dt = this.lastFrame ? Math.min(now - this.lastFrame, 64) : 16;
    this.lastFrame = now;

    for (var i = 0; i < this.packets.length; i++) {
      var p = this.packets[i];
      p.t += p.speed * dt;
      if (p.t > p.len) p.t -= p.len;
    }
    this.drawPackets();

    this.stepElapsed += dt;
    if (this.stepElapsed >= this.stepMs) this.goto(this.step + 1);

    var self = this;
    /* progress bar for the current step */
    var bar = this.fig.querySelector('.sim-progress span');
    if (bar) bar.style.width = Math.min(100, (this.stepElapsed / this.stepMs) * 100) + '%';

    this.raf = requestAnimationFrame(function (t) { self.frame(t); });
  };

  /* ---- boot -------------------------------------------------------- */
  function init() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-sim]'), function (fig) {
      try { new Sim(fig); } catch (e) { /* leave the static figure alone */ }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
