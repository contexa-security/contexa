(function () {
    'use strict';

    document.addEventListener('DOMContentLoaded', function () {
        var banner = document.querySelector('.system-settings-banner-success');
        if (!banner) {
            return;
        }
        window.setTimeout(function () {
            banner.classList.add('is-fading');
        }, 3000);
    });
})();
