/* Cookie Consent Banner – Heritage Bank */
(function () {
    function getCookie(name) {
        var cookieString = document.cookie || '';
        var cookies = cookieString.split(';').map(function (cookie) {
            return cookie.trim().split('=');
        });
        for (var i = 0; i < cookies.length; i++) {
            if (cookies[i][0] === name) {
                try {
                    return decodeURIComponent(cookies[i].slice(1).join('='));
                } catch (e) {
                    return cookies[i].slice(1).join('=');
                }
            }
        }
        return null;
    }

    function setCookie(name, value, days, path) {
        var expires = '';
        if (typeof days === 'number') {
            var date = new Date();
            date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
            expires = '; expires=' + date.toUTCString();
        }
        path = path || '/';
        document.cookie = name + '=' + encodeURIComponent(value) + expires + '; path=' + path;
    }

    function parseConsent(value) {
        if (!value) return null;
        try {
            return JSON.parse(value);
        } catch (e) {
            return null;
        }
    }

    function getConsent() {
        var stored = null;
        try {
            stored = localStorage.getItem('cookieConsent');
        } catch (e) {
            stored = null;
        }
        if (stored) {
            return parseConsent(stored);
        }

        var cookie = getCookie('cookieConsent');
        if (cookie) {
            return parseConsent(cookie);
        }
        return null;
    }

    function saveConsent(prefs) {
        var serialized = JSON.stringify(prefs);
        try {
            localStorage.setItem('cookieConsent', serialized);
        } catch (e) {
            // ignore localStorage errors
        }
        setCookie('cookieConsent', serialized, 365, '/');
    }

    function createSettingsButton() {
        if (document.getElementById('cookie-settings-button')) return;

        var button = document.createElement('button');
        button.id = 'cookie-settings-button';
        button.type = 'button';
        button.className = 'cookie-settings-button';
        button.textContent = 'Cookie Preferences';
        button.title = 'Update your cookie preferences';
        button.addEventListener('click', openBanner);
        document.body.appendChild(button);
    }

    function setButtonVisibility(visible) {
        var button = document.getElementById('cookie-settings-button');
        if (!button) return;
        button.style.display = visible ? 'inline-flex' : 'none';
    }

    function shouldShowBanner() {
        var path = (window.location.pathname || '').split('/').pop() || '';
        var hiddenPages = ['signin.html', 'signup.html', 'forgot-password.html'];
        return hiddenPages.indexOf(path) === -1;
    }

    function openBanner() {
        if (document.getElementById('cookie-consent-banner')) return;
        createBanner(getConsent() || { essential: true, analytics: false, marketing: false });
        setButtonVisibility(false);
    }

    function createBanner(consent) {
        var banner = document.createElement('div');
        banner.id = 'cookie-consent-banner';
        banner.setAttribute('role', 'dialog');
        banner.setAttribute('aria-label', 'Cookie consent');
        banner.innerHTML =
            '<div class="cookie-consent-inner">' +
                '<div class="cookie-consent-copy">' +
                    '<span class="cookie-consent-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M20.2 13.2A8.5 8.5 0 1 1 10.8 3.8a5.2 5.2 0 0 0 9.4 9.4Z"/><path d="M8 8h.01M6.5 13h.01M11 17h.01M14 8h.01"/></svg></span>' +
                    '<div class="cookie-consent-copy-text"><strong class="cookie-consent-title">Your privacy, your choice</strong>' +
                    '<p>We use cookies to make your visit work smoothly and improve the experience. Choose what you’re comfortable with. ' +
                    '<a href="cookie-policy.html">Learn more</a></p></div>' +
                '</div>' +
                '<div id="cookie-categories" class="cookie-categories" style="display:none;">' +
                    '<label class="cookie-cat"><input type="checkbox" checked disabled> <strong>Essential</strong> <span>(always on)</span></label>' +
                    '<label class="cookie-cat"><input type="checkbox" id="ck-analytics"> <strong>Analytics</strong> <span>– helps us improve</span></label>' +
                    '<label class="cookie-cat"><input type="checkbox" id="ck-marketing"> <strong>Marketing</strong> <span>– personalised ads</span></label>' +
                '</div>' +
                '<div class="cookie-consent-buttons">' +
                    '<button type="button" id="cookie-accept-all" class="cookie-btn cookie-btn-accept">Accept All</button>' +
                    '<button type="button" id="cookie-customize" class="cookie-btn cookie-btn-essential">Customize</button>' +
                    '<button type="button" id="cookie-save" class="cookie-btn cookie-btn-accept" style="display:none;">Save Preferences</button>' +
                    '<button type="button" id="cookie-essential" class="cookie-btn cookie-btn-essential">Essential Only</button>' +
                '</div>' +
            '</div>';

        document.body.appendChild(banner);

        document.getElementById('ck-analytics').checked = !!consent.analytics;
        document.getElementById('ck-marketing').checked = !!consent.marketing;

        document.getElementById('cookie-accept-all').addEventListener('click', function () {
            dismiss({ essential: true, analytics: true, marketing: true });
        });
        document.getElementById('cookie-essential').addEventListener('click', function () {
            dismiss({ essential: true, analytics: false, marketing: false });
        });
        document.getElementById('cookie-customize').addEventListener('click', function () {
            document.getElementById('cookie-categories').style.display = 'flex';
            document.getElementById('cookie-save').style.display = '';
            this.style.display = 'none';
        });
        document.getElementById('cookie-save').addEventListener('click', function () {
            dismiss({
                essential: true,
                analytics: !!document.getElementById('ck-analytics').checked,
                marketing: !!document.getElementById('ck-marketing').checked
            });
        });
    }

    function dismiss(prefs) {
        saveConsent(prefs);
        var banner = document.getElementById('cookie-consent-banner');
        if (banner) {
            banner.remove();
        }
        setButtonVisibility(true);
    }

    function createStyle() {
        var style = document.createElement('style');
        style.id = 'cookie-consent-styles';
        style.textContent = `
            #cookie-consent-banner {
                position: fixed; z-index: 10000; left: 50%; bottom: 24px;
                width: min(1020px, calc(100% - 40px)); transform: translateX(-50%);
                padding: 22px 24px; border: 1px solid #e1e9e1; border-radius: 18px;
                background: #fbfcf8; color: #24392b;
                box-shadow: 0 24px 70px rgba(10, 34, 21, .25);
                font-family: Inter, "Segoe UI", sans-serif; font-size: 14px; line-height: 1.55;
                animation: cookieConsentIn .28s ease-out both;
            }
            @keyframes cookieConsentIn {
                from { opacity: 0; transform: translate(-50%, 14px); }
                to { opacity: 1; transform: translate(-50%, 0); }
            }
            .cookie-consent-inner {
                display: grid; grid-template-columns: minmax(0, 1fr) auto;
                align-items: center; gap: 18px 24px; max-width: 1200px; margin: 0 auto;
            }
            .cookie-consent-copy { display: flex; align-items: flex-start; gap: 15px; min-width: 0; }
            .cookie-consent-icon {
                display: grid; flex: 0 0 46px; width: 46px; height: 46px; place-items: center;
                border: 1px solid #dce9dc; border-radius: 14px; background: #edf5ed; color: #27583a;
            }
            .cookie-consent-icon svg { width: 23px; height: 23px; }
            .cookie-consent-copy-text { min-width: 0; }
            .cookie-consent-title { display: block; margin: 0 0 4px; color: #1d3d2a; font-size: 1rem; font-weight: 700; letter-spacing: -.02em; }
            .cookie-consent-inner p { margin: 0; color: #647267; font-size: .88rem; line-height: 1.6; }
            .cookie-consent-inner a { color: #2e6944; font-weight: 650; text-underline-offset: 3px; }
            .cookie-consent-inner a:hover { color: #17452b; }
            .cookie-consent-buttons { display: flex; align-items: center; justify-content: flex-end; gap: 8px; flex-shrink: 0; }
            .cookie-btn {
                min-height: 42px; padding: 10px 15px; border: 1px solid transparent; border-radius: 9px;
                cursor: pointer; font: 650 .82rem/1 Inter, "Segoe UI", sans-serif; white-space: nowrap;
                transition: background .18s ease, border-color .18s ease, transform .18s ease;
            }
            .cookie-btn:hover { transform: translateY(-1px); }
            .cookie-btn:focus-visible, #cookie-settings-button:focus-visible { outline: 3px solid #d3b45f; outline-offset: 3px; }
            .cookie-btn-accept { background: #1c4a31; color: #fff; }
            .cookie-btn-accept:hover { background: #28603f; }
            .cookie-btn-essential { border-color: #d7e0d7; background: #fff; color: #35523e; }
            .cookie-btn-essential:hover { border-color: #aabdaa; background: #f2f7f1; }
            .cookie-btn#cookie-customize { padding-left: 10px; padding-right: 10px; border-color: transparent; background: transparent; color: #3d6548; }
            .cookie-btn#cookie-customize:hover { background: #edf4ed; }
            .cookie-categories {
                grid-column: 1 / -1; display: flex; gap: 10px 20px; flex-wrap: wrap;
                padding: 14px 0 0; border-top: 1px solid #e8eee7;
            }
            .cookie-cat { display: flex; align-items: center; gap: 7px; cursor: pointer; color: #314b38; font-size: .82rem; }
            .cookie-cat input { width: 16px; height: 16px; accent-color: #28603f; }
            .cookie-cat span { color: #7b887e; font-size: .76rem; }
            #cookie-settings-button {
                position: fixed; right: 20px; bottom: 20px; z-index: 10001;
                min-height: 42px; padding: 10px 15px; border: 1px solid rgba(255,255,255,.16); border-radius: 999px;
                background: #173d29; color: #fff; font: 650 .8rem/1 Inter, "Segoe UI", sans-serif;
                cursor: pointer; box-shadow: 0 8px 24px rgba(13, 43, 26, .25);
                transition: transform .18s ease, background .18s ease;
            }
            #cookie-settings-button:hover { transform: translateY(-2px); background: #24583a; }
            @media (max-width: 760px) {
                #cookie-consent-banner { bottom: 12px; width: calc(100% - 24px); padding: 18px; border-radius: 16px; }
                .cookie-consent-inner { grid-template-columns: 1fr; gap: 14px; }
                .cookie-consent-copy { gap: 12px; }
                .cookie-consent-icon { flex-basis: 40px; width: 40px; height: 40px; border-radius: 12px; }
                .cookie-consent-buttons { display: grid; grid-template-columns: 1fr 1fr; width: 100%; gap: 8px; }
                .cookie-btn { padding: 11px 9px; white-space: normal; }
                .cookie-btn#cookie-accept-all { grid-column: 1 / -1; }
                .cookie-categories { gap: 12px; }
                #cookie-settings-button { right: 12px; bottom: 12px; }
            }
            @media (max-width: 380px) {
                #cookie-consent-banner { padding: 15px; }
                .cookie-consent-copy { align-items: flex-start; }
                .cookie-consent-inner p { font-size: .82rem; }
            }
            @media (prefers-reduced-motion: reduce) {
                #cookie-consent-banner { animation: none; }
                .cookie-btn, #cookie-settings-button { transition: none; }
            }
        `;
        return style;
    }

    var styleElement = createStyle();
    if (!document.getElementById(styleElement.id)) {
        document.head.appendChild(styleElement);
    }

    if (getConsent()) {
        createSettingsButton();
    } else if (shouldShowBanner()) {
        openBanner();
    }
})();
