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

  /* ---------- mini demo (landing hero) ---------- */
  function initMini(root) {
    var week = root.querySelector("[data-week]");
    var pdot = root.querySelector("[data-pdot]"), prego = root.querySelector("[data-prego]");
    var sync = root.querySelector(".dm-sync");
    var cells = buildCells(week, false);
    function reset() { cells.forEach(function (c) { c.classList.remove("today"); c.querySelector(".dm-empty").style.display = ""; c.querySelector(".dm-chip").classList.remove("show"); }); if (pdot) pdot.style.background = "var(--line)"; if (prego) prego.textContent = "·"; }
    function done() { cells[TODAY].classList.add("today"); if (pdot) pdot.style.background = CARS[PLAN[TODAY]].v; if (prego) prego.textContent = CARS[PLAN[TODAY]].rego; }
    if (reduced) { PLAN.forEach(function (id, i) { fill(cells[i], id, false); }); done(); return; }
    var steps = [[100, reset]];
    PLAN.forEach(function (id, i) { steps.push([400 + i * 230, function () { fill(cells[i], id, false); }]); });
    steps.push([400 + 7 * 230 + 250, done]);
    steps.push([400 + 7 * 230 + 400, function () { if (sync) { sync.classList.add("pulse"); setTimeout(function () { sync.classList.remove("pulse"); }, 600); } }]);
    loop(steps, 400 + 7 * 230 + 2600);
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
        [1300, function () { place(.82); tap(0); var c = center(cells[0]); picker.style.left = Math.max(6, c.x - 18) + "px"; picker.style.top = (c.y + 12) + "px"; }],
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

  var inits = { mini: initMini, roster: initRoster, oneoff: initOneoff, notify: initNotify, connect: initConnect };
  document.querySelectorAll("[data-demo]").forEach(function (root) {
    var fn = inits[root.getAttribute("data-demo")];
    if (fn) fn(root);
  });
})();
