(function() {
    'use strict';

    var STORAGE_KEY = 'sf_cookie_consent';
    var banner = document.getElementById('cookieBanner');
    var gear = document.getElementById('cookieGear');

    if (!banner) return;

    var consent = getConsent();

    if (consent === null) {
        showBanner();
    } else {
        showGear();
    }

    var acceptBtn = document.getElementById('cookieAcceptAll');
    if (acceptBtn) {
        acceptBtn.addEventListener('click', function() {
            saveConsent('accepted');
            hideBanner();
            showGear();
        });
    }

    var rejectBtn = document.getElementById('cookieRejectAll');
    if (rejectBtn) {
        rejectBtn.addEventListener('click', function() {
            saveConsent('rejected');
            hideBanner();
            showGear();
        });
    }

    if (gear) {
        gear.addEventListener('click', function() {
            showBanner();
            gear.classList.remove('visible');
        });
    }

    function getConsent() {
        try {
            return localStorage.getItem(STORAGE_KEY);
        } catch (e) {
            return null;
        }
    }

    function saveConsent(value) {
        try {
            localStorage.setItem(STORAGE_KEY, value);
        } catch (e) {}
    }

    function showBanner() {
        requestAnimationFrame(function() {
            banner.classList.add('visible');
        });
    }

    function hideBanner() {
        banner.classList.remove('visible');
    }

    function showGear() {
        if (gear) {
            gear.classList.add('visible');
        }
    }
})();
