// Small UI helpers shared by all pages (no build step, plain ES2015+).
(function () {
    'use strict';

    // Translated texts rendered by _Layout.cshtml
    var i18n = {};
    try { i18n = JSON.parse(document.getElementById('i18n').textContent); } catch (e) { }
    var text = function (key, fallback) { return i18n[key] || fallback; };
    window.appText = text;

    // ---------- Theme toggle ----------
    var themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', function () {
            var root = document.documentElement;
            var next = root.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
            root.setAttribute('data-bs-theme', next);
            try { localStorage.setItem('theme', next); } catch (e) { }
        });
    }

    // ---------- Password show/hide ----------
    document.querySelectorAll('input[type="password"]').forEach(function (input) {
        var container = input.closest('.form-floating') || input.parentElement;
        if (!container || container.querySelector('.password-toggle')) return;

        container.classList.add('password-field');
        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'password-toggle';
        button.setAttribute('aria-label', text('showPassword', 'Show password'));
        button.innerHTML = '<i class="bi bi-eye"></i>';
        button.addEventListener('click', function () {
            var show = input.type === 'password';
            input.type = show ? 'text' : 'password';
            button.setAttribute('aria-label', show ? text('hidePassword', 'Hide password') : text('showPassword', 'Show password'));
            button.innerHTML = show ? '<i class="bi bi-eye-slash"></i>' : '<i class="bi bi-eye"></i>';
        });
        input.insertAdjacentElement('afterend', button);
    });

    // ---------- Password strength meter (inputs with data-strength) ----------
    var levels = [
        { label: text('tooWeak', 'Too weak'), cls: 'bg-danger', width: 15 },
        { label: text('weak', 'Weak'), cls: 'bg-danger', width: 35 },
        { label: text('fair', 'Fair'), cls: 'bg-warning', width: 60 },
        { label: text('good', 'Good'), cls: 'bg-info', width: 80 },
        { label: text('strong', 'Strong'), cls: 'bg-success', width: 100 }
    ];

    function scorePassword(value) {
        if (!value) return -1;
        var score = 0;
        if (value.length >= 8) score++;
        if (value.length >= 12) score++;
        if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score++;
        if (/\d/.test(value)) score++;
        if (/[^A-Za-z0-9]/.test(value)) score++;
        if (value.length < 8) score = Math.min(score, 1);
        return Math.min(score, 4);
    }

    document.querySelectorAll('input[data-strength]').forEach(function (input) {
        var container = input.closest('.form-floating') || input.parentElement;
        var meter = document.createElement('div');
        meter.className = 'password-strength';
        meter.hidden = true;
        meter.innerHTML =
            '<div class="progress" role="progressbar" aria-label="Password strength"><div class="progress-bar"></div></div>' +
            '<small class="d-block mt-1"></small>';
        container.insertAdjacentElement('afterend', meter);

        var bar = meter.querySelector('.progress-bar');
        var hint = meter.querySelector('small');

        input.addEventListener('input', function () {
            var score = scorePassword(input.value);
            meter.hidden = score < 0;
            if (score < 0) return;
            var level = levels[score];
            bar.className = 'progress-bar ' + level.cls;
            bar.style.width = level.width + '%';
            hint.textContent = level.label + ' - ' + text('strengthHint', 'use 8+ characters with upper- and lowercase letters, a digit and a symbol.');
        });
    });

    // ---------- Copy to clipboard ----------
    document.querySelectorAll('[data-copy-target]').forEach(function (button) {
        button.addEventListener('click', function () {
            var target = document.querySelector(button.getAttribute('data-copy-target'));
            if (!target || !navigator.clipboard) return;
            var value = target.getAttribute('data-copy-text') || target.innerText;
            navigator.clipboard.writeText(value.trim()).then(function () {
                var original = button.innerHTML;
                button.innerHTML = '<i class="bi bi-check2"></i> ' + text('copied', 'Copied');
                setTimeout(function () { button.innerHTML = original; }, 1500);
            });
        });
    });

    // ---------- Download text (recovery codes) ----------
    document.querySelectorAll('[data-download-target]').forEach(function (button) {
        button.addEventListener('click', function () {
            var target = document.querySelector(button.getAttribute('data-download-target'));
            if (!target) return;
            var content = target.getAttribute('data-copy-text') || target.innerText;
            var blob = new Blob([content.trim() + '\n'], { type: 'text/plain' });
            var link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = button.getAttribute('data-filename') || 'download.txt';
            document.body.appendChild(link);
            link.click();
            link.remove();
            URL.revokeObjectURL(link.href);
        });
    });

    // ---------- Confirm dangerous actions ----------
    document.querySelectorAll('form[data-confirm]').forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!window.confirm(form.getAttribute('data-confirm'))) {
                event.preventDefault();
            }
        });
    });
})();
