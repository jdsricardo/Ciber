// Progressive enhancement: the page works without JS; this only adds convenience.
(function () {
    'use strict';

    // Copy the "fixed" code example to the clipboard.
    document.addEventListener('click', function (event) {
        var button = event.target.closest('.copy-fix');
        if (!button) {
            return;
        }
        var figure = button.closest('.code-example');
        var pre = figure && figure.querySelector('pre');
        if (!pre) {
            return;
        }
        var done = function () {
            var original = button.textContent;
            button.textContent = button.dataset.copied || 'Copiado!';
            button.classList.add('is-copied');
            setTimeout(function () {
                button.textContent = original;
                button.classList.remove('is-copied');
            }, 1600);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(pre.textContent).then(done, done);
        } else {
            var range = document.createRange();
            range.selectNodeContents(pre);
            var sel = window.getSelection();
            sel.removeAllRanges();
            sel.addRange(range);
            try { document.execCommand('copy'); } catch (e) { /* ignore */ }
            sel.removeAllRanges();
            done();
        }
    });

    // Severity filter chips on the results page.
    var filter = document.querySelector('[data-severity-filter]');
    if (filter) {
        var findings = Array.prototype.slice.call(document.querySelectorAll('.finding[data-severity]'));
        filter.addEventListener('click', function (event) {
            var chip = event.target.closest('[data-filter]');
            if (!chip) {
                return;
            }
            var want = chip.getAttribute('data-filter');
            filter.querySelectorAll('[data-filter]').forEach(function (c) {
                c.classList.toggle('active', c === chip);
            });
            findings.forEach(function (el) {
                el.hidden = !(want === 'all' || el.getAttribute('data-severity') === want);
            });
        });
    }
})();
