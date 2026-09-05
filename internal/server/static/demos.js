// p.stonn "how it works" animations. Vanilla JS, no dependencies. Each demo runs
// only if its container is on the page, so this one file serves the landing mini
// demo and the full /why gallery. Sample data only: made-up plates and names.
(function () {
  "use strict";
  var reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  var CARS = {
    1: { rego: "ABC123", name: "Nan's car", v: "var(--v1)" },
    2: { rego: "XYZ789", name: "Nanny", v: "var(--v2)" },
    3: { rego: "1QW4RT", name: "Babysitter", v: "var(--v3)" }
  };
  var PLAN = [1, 1, 1, 1, 1, 2, 3], TODAY = 2;
  var DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

  function loop(steps, period) {
    var timers = [];
    (function cycle() {
      timers.forEach(clearTimeout); timers = [];
      steps.forEach(function (s) { timers.push(setTimeout(s[1], s[0])); });
      timers.push(setTimeout(cycle, period));
    })();
  }
  function show(el, on) { if (el) el.classList.toggle("show", on !== false); }
  function buildCells(week, withRego) {
    return DAYS.map(function (d) {
      var c = document.createElement("div"); c.className = "dm-day";
      c.innerHTML = '<div class="dm-dname">' + d + '</div><div class="dm-empty">&middot;</div>' +
        '<div class="dm-chip"><span class="dm-dot"></span>' + (withRego ? '<span class="dm-rego"></span>' : '') + '</div>';
      week.appendChild(c); return c;
    });
  }
  function fill(cell, id, withRego) {
    var car = CARS[id];
    cell.querySelector(".dm-empty").style.display = "none";
    var ch = cell.querySelector(".dm-chip");
    ch.querySelector(".dm-dot").style.background = car.v;
    if (withRego) ch.querySelector(".dm-rego").textContent = car.rego;
    ch.classList.add("show");
  }

  /* ---------- landing showcase: a captioned story on one phone ----------
     Four beats — build the weekly schedule, sync it to the council permit,
     notify, then share a guest link — so the hero conveys the whole feature
     set instead of a single static week. Overlay cards slide over the phone
     top for the notify + share beats. */
  function initShowcase(root) {
    var week = root.querySelector("[data-week]");
    var pdot = root.querySelector("[data-pdot]"), prego = root.querySelector("[data-prego]");
    var sync = root.querySelector(".dm-sync"), cap = root.querySelector("[data-cap] span");
    var push = root.querySelector("[data-push]"), guest = root.querySelector("[data-guest]");
    var cells = buildCells(week, false);
    function say(h) { if (!cap) return; cap.classList.remove("show"); setTimeout(function () { cap.innerHTML = h; cap.classList.add("show"); }, 170); }
    function settle() { cells[TODAY].classList.add("today"); if (pdot) pdot.style.background = CARS[PLAN[TODAY]].v; if (prego) prego.textContent = CARS[PLAN[TODAY]].rego; }
    function reset() {
      cells.forEach(function (c) { c.classList.remove("today"); c.querySelector(".dm-empty").style.display = ""; c.querySelector(".dm-chip").classList.remove("show"); });
      if (pdot) pdot.style.background = "var(--line)"; if (prego) prego.textContent = "·";
      show(push, false); show(guest, false);
    }
    if (reduced) {
      PLAN.forEach(function (id, i) { fill(cells[i], id, false); }); settle();
      if (cap) { cap.innerHTML = "A weekly schedule that keeps your council permit in sync."; cap.classList.add("show"); }
      return;
    }
    var steps = [[100, reset], [260, function () { say("Set which car is on your permit each day."); }]];
    PLAN.forEach(function (id, i) { steps.push([620 + i * 200, function () { fill(cells[i], id, false); }]); });
    steps.push([2300, function () { say("<b>p.stonn sets your council permit to match &mdash; automatically.</b>"); }]);
    steps.push([2560, function () { settle(); if (sync) { sync.classList.add("pulse"); setTimeout(function () { sync.classList.remove("pulse"); }, 600); } }]);
    steps.push([4300, function () { say("You get an email or push each time it changes."); }]);
    steps.push([4500, function () { show(push, true); }]);
    steps.push([6600, function () { show(push, false); }]);
    steps.push([7050, function () { say("Or share a link so visitors set their own car."); }]);
    steps.push([7250, function () { show(guest, true); }]);
    steps.push([9500, function () { show(guest, false); }]);
    loop(steps, 10600);
  }

  /* ---------- Demo A: weekly roster (full, with cursor + picker) ---------- */
  function initRoster(root) {
    var phone = root.querySelector(".dm-phone"), week = root.querySelector("[data-week]");
    var cursor = root.querySelector(".dm-cursor"), picker = root.querySelector(".dm-picker");
    var sync = root.querySelector(".dm-sync"), pdot = root.querySelector("[data-pdot]"), prego = root.querySelector("[data-prego]");
    var cap = root.querySelector(".dm-caption span");
    var cells = buildCells(week, true);
    function reset() { cells.forEach(function (c) { c.classList.remove("today"); c.querySelector(".dm-empty").style.display = ""; c.querySelector(".dm-chip").classList.remove("show"); }); pdot.style.background = "var(--line)"; prego.textContent = "·"; picker.classList.remove("show"); cursor.classList.remove("on"); }
    function say(h) { cap.classList.remove("show"); setTimeout(function () { cap.innerHTML = h; cap.classList.add("show"); }, 170); }
    function center(el) { var pr = phone.getBoundingClientRect(), r = el.getBoundingClientRect(); return { x: r.left - pr.left + r.width / 2 - 3, y: r.top - pr.top + r.height / 2 - 2 }; }
    var cpos = { x: 0, y: 0 };
    function place(s) { cursor.style.transform = "translate(" + cpos.x + "px," + cpos.y + "px) scale(" + (s || 1) + ")"; }
    function moveTo(el) { cpos = center(el); place(1); cursor.classList.add("on"); }
    function tap(i) { cells[i].classList.add("tap"); setTimeout(function () { cells[i].classList.remove("tap"); }, 200); }

    if (reduced) { PLAN.forEach(function (id, i) { fill(cells[i], id, true); }); cells[TODAY].classList.add("today"); pdot.style.background = CARS[PLAN[TODAY]].v; prego.textContent = CARS[PLAN[TODAY]].rego; cap.innerHTML = "Set a car for each day. <b>p.stonn keeps the council permit in sync.</b>"; cap.classList.add("show"); return; }

    function build() {
      return [
        [150, function () { reset(); say("Pick a car for each day."); }],
        [700, function () { moveTo(cells[0]); }],
        [1300, function () {
          place(.82); tap(0); var c = center(cells[0]);
          // Clamp inside the phone so overflow:hidden can never clip the picker
          // (it did at phone widths, where the card is shorter than the dropdown).
          var pw = picker.offsetWidth, ph2 = picker.offsetHeight, PW = phone.clientWidth, PH = phone.clientHeight;
          var left = Math.max(6, Math.min(c.x - 18, PW - pw - 6));
          var top = Math.max(6, Math.min(c.y + 12, PH - ph2 - 6));
          picker.style.left = left + "px"; picker.style.top = top + "px";
        }],
        [1480, function () { place(1); picker.classList.add("show"); }],
        [2000, function () { var o = picker.querySelector('[data-v="1"]'); o.classList.add("hot"); moveTo(o); }],
        [2560, function () { place(.82); }],
        [2740, function () { place(1); picker.classList.remove("show"); picker.querySelector('[data-v="1"]').classList.remove("hot"); fill(cells[0], 1, true); }],
        [3050, function () { say("Weekdays stay the same, so set them once."); }],
        [3250, function () { fill(cells[1], 1, true); tap(1); }],
        [3450, function () { fill(cells[2], 1, true); tap(2); }],
        [3650, function () { fill(cells[3], 1, true); tap(3); }],
        [3850, function () { fill(cells[4], 1, true); tap(4); }],
        [4300, function () { say("Give the weekend different cars if you like."); moveTo(cells[5]); }],
        [4650, function () { place(.82); tap(5); }],
        [4820, function () { place(1); fill(cells[5], 2, true); }],
        [5050, function () { moveTo(cells[6]); }],
        [5400, function () { place(.82); tap(6); }],
        [5570, function () { place(1); fill(cells[6], 3, true); cursor.classList.remove("on"); }],
        [6050, function () { say("<b>p.stonn sets your council permit to match, automatically.</b>"); }],
        [6300, function () { cells[TODAY].classList.add("today"); }],
        [6600, function () { pdot.style.background = CARS[PLAN[TODAY]].v; prego.textContent = CARS[PLAN[TODAY]].rego; sync.classList.add("pulse"); }],
        [7200, function () { sync.classList.remove("pulse"); }],
        [7900, function () { say("No more logging in every time someone helps with the kids."); }]
      ];
    }
    requestAnimationFrame(function () { requestAnimationFrame(function () { loop(build(), 10600); }); });
    var rt; addEventListener("resize", function () { clearTimeout(rt); rt = setTimeout(reset, 150); });
  }

  /* ---------- Demo B: one-off booking ---------- */
  function initOneoff(root) {
    var flds = [].slice.call(root.querySelectorAll(".dm-fld"));
    var vals = flds.map(function (f) { return f.querySelector(".val .dm-fade") || f.querySelector(".val"); });
    var btn = root.querySelector(".dm-btn"), bres = root.querySelector(".dm-booking"), cal = root.querySelector(".dm-cal");
    var mini = ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"];
    var dots = mini.map(function (d) { var w = document.createElement("div"); w.innerHTML = '<div class="dm-calday">' + d + '</div><div class="dm-caldot"></div>'; cal.appendChild(w); return w.querySelector(".dm-caldot"); });
    function reset() { vals.forEach(function (v) { v.classList.remove("show"); }); flds.forEach(function (f) { f.classList.remove("lit"); }); bres.classList.remove("show"); dots.forEach(function (d) { d.classList.remove("on"); }); }
    if (reduced) { vals.forEach(function (v) { v.classList.add("show"); }); bres.classList.add("show"); dots[5].classList.add("on"); dots[6].classList.add("on"); return; }
    loop([
      [150, reset],
      [500, function () { flds[0].classList.add("lit"); show(vals[0]); }],
      [800, function () { flds[0].classList.remove("lit"); }],
      [1050, function () { flds[1].classList.add("lit"); show(vals[1]); }],
      [1350, function () { flds[1].classList.remove("lit"); }],
      [1600, function () { flds[2].classList.add("lit"); show(vals[2]); }],
      [1900, function () { flds[2].classList.remove("lit"); }],
      [2300, function () { btn.classList.add("press"); }],
      [2500, function () { btn.classList.remove("press"); }],
      [2750, function () { show(bres); dots[5].classList.add("on"); dots[6].classList.add("on"); }]
    ], 6200);
  }

  /* ---------- Demo C: notifications ---------- */
  function initNotify(root) {
    var pushes = [].slice.call(root.querySelectorAll(".dm-push"));
    if (reduced) { pushes.forEach(function (p) { p.classList.add("show"); }); return; }
    loop([
      [150, function () { pushes.forEach(function (p) { p.classList.remove("show"); }); }],
      [600, function () { show(pushes[0]); }],
      [3200, function () { if (pushes[1]) show(pushes[1]); }]
    ], 7200);
  }

  /* ---------- Demo D: connect ---------- */
  function initConnect(root) {
    var dots = root.querySelector("[data-pw]"), fld = dots.closest(".dm-fld"), btn = root.querySelector(".dm-btn"), res = root.querySelector(".dm-result");
    if (reduced) { dots.textContent = "•••••••••"; res.classList.add("show"); return; }
    var N = 9, steps = [[150, function () { dots.textContent = ""; fld.classList.remove("lit"); res.classList.remove("show"); }], [500, function () { fld.classList.add("lit"); }]];
    for (var i = 1; i <= N; i++) { (function (n) { steps.push([600 + n * 130, function () { dots.textContent = new Array(n + 1).join("•"); }]); })(i); }
    steps.push([2100, function () { fld.classList.remove("lit"); }]);
    steps.push([2350, function () { btn.classList.add("press"); }]);
    steps.push([2550, function () { btn.classList.remove("press"); }]);
    steps.push([2850, function () { res.classList.add("show"); }]);
    loop(steps, 6600);
  }

  /* ---------- shared bits for the flow demos ---------- */
  // Caption helper bound to a root's .dm-caption span.
  function sayer(root) {
    var cap = root.querySelector(".dm-caption span");
    return function (h) { if (!cap) return; cap.classList.remove("show"); setTimeout(function () { cap.innerHTML = h; cap.classList.add("show"); }, 170); };
  }
  // A visitor-status line: spinner + text, or a tick + text.
  function statSpin(el, html) { el.classList.remove("ok"); el.innerHTML = '<span class="dm-spin"></span><span>' + html + "</span>"; }
  function statOk(el, html) {
    el.classList.add("ok");
    el.innerHTML = '<span class="dm-vtick"><svg viewBox="0 0 24 24"><path d="M5 13l4 4 10-11"/></svg></span><span>' + html + "</span>";
  }
  function press(btn) { btn.classList.add("press"); setTimeout(function () { btn.classList.remove("press"); }, 200); }
  function pulse(sync) { if (!sync) return; sync.classList.add("pulse"); setTimeout(function () { sync.classList.remove("pulse"); }, 600); }

  /* ---------- Demo E: a guest pass (the guest's own page) ---------- */
  function initGuestpass(root) {
    var cars = [].slice.call(root.querySelectorAll(".dm-gcar"));
    var gdot = root.querySelector("[data-gdot]"), grego = root.querySelector("[data-grego]");
    var guntil = root.querySelector("[data-guntil]"), sync = root.querySelector(".dm-sync");
    var mail = root.querySelector("[data-gpmail]"), say = sayer(root);
    var CHOICE = 2; // the guest taps car 2 (XYZ789, "Nanny")
    function pick() { return cars.filter(function (c) { return c.getAttribute("data-g") === String(CHOICE); })[0]; }
    function settle() {
      var car = CARS[CHOICE];
      gdot.style.background = car.v; grego.textContent = car.rego; guntil.textContent = "until the end of today";
    }
    if (reduced) {
      show(mail, true);
      cars.forEach(function (c) { c.classList.add("in"); });
      pick().classList.add("on"); settle();
      var cap = root.querySelector(".dm-caption span");
      if (cap) { cap.innerHTML = "They tap their car — <b>on until the end of today</b>, and you're told."; cap.classList.add("show"); }
      return;
    }
    function reset() {
      cars.forEach(function (c) { c.classList.remove("in", "on"); });
      gdot.style.background = "var(--line)"; grego.textContent = "·"; guntil.textContent = "";
      show(mail, false);
    }
    var steps = [
      [150, reset],
      [300, function () { say("Send the pass once &mdash; they keep the link."); }],
      [700, function () { show(mail, true); }],
      [2900, function () { show(mail, false); say("When they arrive, they tap their car."); }]
    ];
    cars.forEach(function (c, i) { steps.push([3300 + i * 200, function () { c.classList.add("in"); }]); });
    steps.push([4500, function () { pick().classList.add("on"); }]);
    steps.push([4800, function () { guntil.textContent = "applying…"; }]);
    steps.push([5600, function () { settle(); pulse(sync); }]);
    steps.push([5900, function () { say("<b>On until the end of today</b> &mdash; and you're told each time."); }]);
    loop(steps, 9200);
  }

  /* ---------- Demo F: add a visitor with a QR (on-screen code) ---------- */
  function initVisitorqr(root) {
    var dot = root.querySelector("[data-vqdot]"), rego = root.querySelector("[data-vqrego]"), until = root.querySelector("[data-vquntil]");
    var btn = root.querySelector("[data-vqbtn]"), qr = root.querySelector("[data-vqqr]"), guest = root.querySelector("[data-vqguest]");
    var fld = root.querySelector("[data-vqfld]"), put = root.querySelector("[data-vqput]"), stat = root.querySelector("[data-vqstat]");
    var plate = fld.querySelector(".dm-fade"), sync = root.querySelector(".dm-sync"), say = sayer(root);
    function settle() { dot.style.background = CARS[2].v; rego.textContent = CARS[2].rego; until.textContent = "until the end of today"; }
    function reset() {
      show(qr, false); show(guest, false); show(plate, false);
      fld.classList.remove("lit"); stat.innerHTML = ""; stat.classList.remove("ok");
      dot.style.background = CARS[1].v; rego.textContent = CARS[1].rego; until.textContent = "";
    }
    if (reduced) {
      show(qr, true); settle();
      var cap = root.querySelector(".dm-caption span");
      if (cap) { cap.innerHTML = "The visitor scans this, types their plate &mdash; <b>done</b>. It stops working after 15 minutes."; cap.classList.add("show"); }
      return;
    }
    loop([
      [150, reset],
      [300, function () { say("A visitor arrives &mdash; tap <b>Show visitor QR</b>."); }],
      [1300, function () { press(btn); }],
      [1550, function () { show(qr, true); }],
      [2700, function () { say("They scan it straight off your screen."); }],
      [4100, function () { show(guest, true); say("No app, no account &mdash; they type their plate."); }],
      [4800, function () { fld.classList.add("lit"); show(plate, true); }],
      [5300, function () { fld.classList.remove("lit"); }],
      [5800, function () { press(put); }],
      [6100, function () { statSpin(stat, "Changing to <b>XYZ789</b>&hellip;"); }],
      [7400, function () { statOk(stat, "<b>XYZ789</b> is on the permit until the end of today."); }],
      [8800, function () { show(guest, false); say("<b>Done.</b> The code stops working after 15 minutes."); }],
      [9000, function () { settle(); pulse(sync); }]
    ], 11800);
  }

  /* ---------- Demo G: the printed QR (fridge → your mobile) ---------- */
  function initDoorqr(root) {
    var paper = root.querySelector("[data-dqpaper]"), push = root.querySelector("[data-dqpush]");
    var done = root.querySelector("[data-dqdone]"), ok = root.querySelector("[data-dqok]");
    var say = sayer(root);
    function reset() { show(push, false); show(done, false); paper.classList.remove("lit"); }
    if (reduced) {
      show(done, true);
      var cap = root.querySelector(".dm-caption span");
      if (cap) { cap.innerHTML = "A scan only <b>asks</b> &mdash; nothing goes on the permit until you approve it from your phone."; cap.classList.add("show"); }
      return;
    }
    loop([
      [150, reset],
      [300, function () { say("Print it once &mdash; it can live on the fridge for years."); }],
      [2300, function () { paper.classList.add("lit"); say("A visitor scans it and asks to use the permit."); }],
      [3100, function () { paper.classList.remove("lit"); }],
      [4300, function () { show(push, true); say("Your phone gets the request, wherever you are."); }],
      [6600, function () { press(ok); }],
      [7000, function () { show(push, false); show(done, true); }],
      [7600, function () { say("<b>Nothing goes on the permit until you say yes.</b>"); }]
    ], 10600);
  }

  var inits = { showcase: initShowcase, roster: initRoster, oneoff: initOneoff, notify: initNotify, connect: initConnect, guestpass: initGuestpass, visitorqr: initVisitorqr, doorqr: initDoorqr };
  function initDemos() {
    document.querySelectorAll("[data-demo]").forEach(function (root) {
      if (root.dataset.demoInit) return; // already running
      var fn = inits[root.getAttribute("data-demo")];
      if (fn) {
        root.dataset.demoInit = "1";
        fn(root);
      }
    });
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initDemos);
  } else {
    initDemos();
  }
  // htmx boosted navigation swaps the body without re-running head scripts, so
  // re-scan for freshly-swapped demos after each load.
  document.addEventListener("htmx:load", initDemos);
})();
