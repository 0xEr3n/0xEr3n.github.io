document.addEventListener('DOMContentLoaded', function () {
  /* Jekyll/Rouge generates:
       <div class="language-python highlighter-rouge">
         <div class="highlight">
           <pre class="highlight"><code>...</code></pre>
         </div>
       </div>
     We inject a .code-header above each <pre> with:
       [● ● ●]  [  language  ]  [copy] */

  document.querySelectorAll('.highlighter-rouge').forEach(function (wrapper) {
    var highlight = wrapper.querySelector('.highlight');
    var pre       = wrapper.querySelector('pre');
    if (!highlight || !pre) return;

    var match = wrapper.className.match(/language-([\w+-]+)/);
    var lang  = match ? match[1] : '';

    /* ── Build header ───────────────────────────────── */
    var header = document.createElement('div');
    header.className = 'code-header';

    /* Window dots */
    var dots = document.createElement('div');
    dots.className = 'code-dots';
    for (var i = 0; i < 3; i++) {
      var dot = document.createElement('span');
      dot.className = 'code-dot';
      dots.appendChild(dot);
    }

    /* Language label */
    var label = document.createElement('span');
    label.className   = 'code-lang';
    label.textContent = lang || 'code';

    /* Copy button */
    var btn = document.createElement('button');
    btn.className   = 'copy-btn';
    btn.textContent = 'copy';
    btn.setAttribute('aria-label', 'Copy code to clipboard');

    btn.addEventListener('click', function () {
      var code = pre.querySelector('code') || pre;
      var text = code.innerText;

      navigator.clipboard.writeText(text).then(function () {
        btn.textContent = 'copied!';
        btn.classList.add('copied');
        setTimeout(function () {
          btn.textContent = 'copy';
          btn.classList.remove('copied');
        }, 2000);
      }).catch(function () {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;opacity:0;';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch (_) {}
        document.body.removeChild(ta);
        btn.textContent = 'copied!';
        setTimeout(function () { btn.textContent = 'copy'; }, 2000);
      });
    });

    header.appendChild(dots);
    header.appendChild(label);
    header.appendChild(btn);
    highlight.insertBefore(header, pre);
  });
});
