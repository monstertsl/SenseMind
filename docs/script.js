// SenseMind — 导航、入场动画、背景视差、段落氛围切换、复制
(function () {
  "use strict";
  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---- 导航栏：常驻固定；顶部与页面融合，滚动后变独立玻璃条 ----
  var nav = document.getElementById("nav");
  function onScrollNav() {
    nav.classList.add("visible");
    nav.classList.toggle("scrolled", window.scrollY > 24);
  }
  window.addEventListener("scroll", onScrollNav, { passive: true });
  requestAnimationFrame(onScrollNav);

  // ---- 滚动进入视口时播放一次入场 ----
  function observeOnce(el, cls) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          el.classList.add(cls);
          io.disconnect();
        }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -40px 0px" });
    io.observe(el);
  }
  document.querySelectorAll(".reveal").forEach(function (el) { observeOnce(el, "in"); });
  ["pipeline", "valueGrid"].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) observeOnce(el, "in");
  });
  var grid = document.querySelector(".feature-grid");
  if (grid) observeOnce(grid, "in");

  // ---- 底层线框：随页面滑动但速度约为页面 35%，双份内容取模实现无缝循环 ----
  var track = document.getElementById("bgTrack");
  if (track && track.children.length === 1) {
    track.appendChild(track.children[0].cloneNode(true));
  }
  var ticking = false;
  function parallax() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(function () {
      if (!reduceMotion && track) {
        // 循环周期 = 3 屏，长图三段内容滚完才回到起点，重复感更低
        var vh = window.innerHeight || 800;
        var period = vh * 3;
        var y = -((window.scrollY * 0.35) % period);
        track.style.transform = "translate3d(0," + Math.round(y) + "px,0)";
      }
      ticking = false;
    });
  }
  window.addEventListener("scroll", parallax, { passive: true });
  window.addEventListener("resize", parallax, { passive: true });
  parallax();

  // ---- 当前段落 → body[data-section]（用视口中线判定，长屏也能命中） ----
  var sections = document.querySelectorAll("section.screen");
  var secIO = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (e.isIntersecting) {
        document.body.dataset.section = e.target.id || "hero";
      }
    });
  }, { rootMargin: "-45% 0px -45% 0px", threshold: 0 });
  sections.forEach(function (s) { secIO.observe(s); });

  // ---- 复制部署命令 ----
  var btn = document.getElementById("copyBtn");
  var code = document.getElementById("deployCode");
  if (btn && code) {
    btn.addEventListener("click", function () {
      var text = code.textContent.replace(/\s*#.*$/gm, "").trim();
      function done() {
        btn.textContent = "已复制";
        btn.classList.add("done");
        setTimeout(function () {
          btn.textContent = "复制";
          btn.classList.remove("done");
        }, 1600);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () {});
      } else {
        var ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); done(); } catch (e) {}
        document.body.removeChild(ta);
      }
    });
  }

  // ---- Hero 堆叠轮播：定期把下一张翻到最前；竖屏只留 dashboard 并暂停 ----
  var stack = document.getElementById("heroStack");
  if (stack) {
    var cards = Array.prototype.slice.call(stack.querySelectorAll(".stack-card"));
    var dots = Array.prototype.slice.call(stack.querySelectorAll(".stack-dot"));
    var stackMq = window.matchMedia("(max-width: 900px)");
    var stackOffset = 0, stackTimer = null;
    function renderStack() {
      var n = cards.length;
      for (var i = 0; i < n; i++) cards[i].dataset.pos = String((i - stackOffset + n) % n);
      dots.forEach(function (d, i) { d.classList.toggle("on", i === stackOffset); });
    }
    function stopStack() { if (stackTimer) { clearInterval(stackTimer); stackTimer = null; } }
    function startStack() {
      stopStack();
      if (!reduceMotion && !stackMq.matches) {
        stackTimer = setInterval(function () {
          stackOffset = (stackOffset + 1) % cards.length;
          renderStack();
        }, 4500);
      }
    }
    dots.forEach(function (d, i) {
      d.addEventListener("click", function () { stackOffset = i; renderStack(); });
    });
    if (stackMq.addEventListener) {
      stackMq.addEventListener("change", function () {
        stackOffset = 0; // 回到 dashboard
        renderStack();
        startStack();
      });
    }
    renderStack();
    startStack();
  }
})();
