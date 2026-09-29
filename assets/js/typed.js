(function () {
  var el = document.querySelector('.typed');
  if (!el) return;
  var text = el.getAttribute('data-text') || '';
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    el.textContent = text;
    return;
  }
  var i = 0;
  (function tick() {
    el.textContent = text.slice(0, ++i);
    if (i < text.length) setTimeout(tick, 90 + Math.random() * 80);
  })();
})();
