/*! MARU fold-nav — NAS/file:///mobile safe */
(function () {
  if (window.__MARU_FOLD_NAV__) return;
  window.__MARU_FOLD_NAV__ = true;

  function scriptBase() {
    var nodes = document.getElementsByTagName("script");
    for (var i = nodes.length - 1; i >= 0; i--) {
      var el = nodes[i];
      var attr = el.getAttribute("src") || "";
      if (!/fold-nav\.js/i.test(attr)) continue;
      var abs = el.src || "";
      if (!abs) continue;
      // .../_shared/fold-nav.js -> dashboard root
      return abs.replace(/[^/]*fold-nav\.js(?:\?.*)?$/i, "").replace(/_shared\/$/i, "");
    }
    return null;
  }

  function pathPrefix() {
    var p = (location.pathname || "").replace(/\\/g, "/");
    var i = p.toLowerCase().lastIndexOf("/dashboard/");
    if (i < 0) return null;
    var rest = p.slice(i + "/dashboard/".length);
    var parts = rest.split("/").filter(Boolean);
    if (parts.length && /\.html?$/i.test(parts[parts.length - 1])) parts.pop();
    if (!parts.length) return "./";
    return "../".repeat(parts.length);
  }

  function relPrefix() {
    // Prefer path-relative (works with file:// and keeps Korean paths stable)
    var fromPath = pathPrefix();
    if (fromPath != null) return fromPath;
    var base = scriptBase();
    if (base) return base; // absolute file URL to dashboard root
    return "./";
  }

  function currentKey() {
    var p = (location.pathname || "").replace(/\\/g, "/");
    var pl = p.toLowerCase();
    var i = pl.lastIndexOf("/dashboard/");
    var rest = i >= 0 ? p.slice(i + "/dashboard/".length) : p;
    var rl = rest.toLowerCase();
    if (!rest || /^index\.html$/i.test(rest)) return "home";
    if (rest.indexOf("봉제현황") === 0 || rl.indexOf("%eb%b4%89%ec%a0%9c%ed%98%84%ed%99%a9") === 0) return "bongje";
    if (rl.indexOf("goodtrust") === 0) return "gt";
    if (rest.indexOf("두리콜렉션") === 0 || rl.indexOf("%eb%91%90%eb%a6%ac") === 0) return "duri";
    if (rl.indexOf("status") === 0) return "status";
    if (rl.indexOf("process") === 0) return "process";
    if (rl.indexOf("sales") === 0) return "sales";
    if (rl.indexOf("education/_errors") === 0 || rl.indexOf("education/%5ferrors") === 0) return "errors";
    if (rl.indexOf("education") === 0) return "edu";
    if (rest.indexOf("사후정산") === 0) return "settle";
    return "";
  }

  var up = relPrefix();
  var items = [
    { key: "home", href: up + "index.html", label: "폴더홈", home: true },
    { key: "bongje", href: up + "봉제현황/index.html", label: "봉제현황" },
    { key: "gt", href: up + "goodtrust/index.html", label: "GOODTRUST" },
    { key: "duri", href: up + "두리콜렉션/index.html", label: "두리콜렉션" },
    { key: "status", href: up + "status/index.html", label: "생산현황" },
    { key: "process", href: up + "process/index.html", label: "공정" },
    { key: "sales", href: up + "sales/index.html", label: "매출" },
    { key: "settle", href: up + "사후정산/index.html", label: "사후정산", nasOnly: true },
    { key: "edu", href: up + "education/index.html", label: "교육자료" },
    { key: "errors", href: up + "education/_errors/index.html", label: "오답노트" }
  ];
  // 2026-10-17 takedown v3: 사후정산은 NAS 전용 - 웹(file: 아님)에서는 메뉴에서 뺌
  if (location.protocol !== "file:") items = items.filter(function (it) { return !it.nasOnly; });
  var cur = currentKey();

  var nav = document.createElement("nav");
  nav.className = "fold-nav";
  nav.setAttribute("aria-label", "대시보드 바로가기");
  items.forEach(function (it) {
    var a = document.createElement("a");
    a.href = it.href;
    a.textContent = it.label;
    if (it.home) a.classList.add("home");
    if (it.key === cur) a.classList.add("on");
    nav.appendChild(a);
  });

  document.querySelectorAll("nav.fold-nav").forEach(function (n) { n.remove(); });
  var body = document.body;
  if (!body) return;
  if (body.firstChild) body.insertBefore(nav, body.firstChild);
  else body.appendChild(nav);
})();
