// FileKey blog — the one script on the page: a light/dark/auto theme switch.
// Loaded synchronously in <head> so the theme is set before first paint (no flash).
// No tracking, no network, no cookies — preference lives in localStorage only.
(function () {
  var el = document.documentElement;
  function pref() { try { return localStorage.getItem("fk-theme") || "auto"; } catch (e) { return "auto"; } }
  function apply(p) { if (p === "auto") el.removeAttribute("data-theme"); else el.setAttribute("data-theme", p); }
  apply(pref()); // before paint

  var ICON = {
    auto: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none"/></svg>',
    light: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>',
    dark: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'
  };
  var LABEL = { auto: "Theme: auto", light: "Theme: light", dark: "Theme: dark" };
  var ORDER = ["auto", "light", "dark"];

  function wire() {
    var btn = document.getElementById("themeBtn");
    if (!btn) return;
    function render() { var p = pref(); btn.innerHTML = ICON[p]; btn.setAttribute("aria-label", LABEL[p] + " (tap to change)"); }
    render();
    btn.addEventListener("click", function () {
      var next = ORDER[(ORDER.indexOf(pref()) + 1) % ORDER.length];
      try { localStorage.setItem("fk-theme", next); } catch (e) {}
      apply(next); render();
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", wire);
  else wire();
})();
