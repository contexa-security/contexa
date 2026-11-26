/*
 * The user bridge status screen (/contexa/admin/zero-trust/bridge). The server writes every count, share and word; this
 * script only gives each bar the width of its share (data-share, between 0 and 1), so the page holds no inline style.
 */
(function () {
    'use strict';

    function widthOf(element) {
        var share = parseFloat(element.getAttribute('data-share'));
        if (!isFinite(share) || share < 0) {
            share = 0;
        }
        return (Math.min(1, share) * 100) + '%';
    }

    document.addEventListener('DOMContentLoaded', function () {
        var page = document.querySelector('.bs-page');
        if (!page) {
            return;
        }
        page.querySelectorAll('.bs-bar-fill[data-share], .bs-stacked-part[data-share]').forEach(function (element) {
            element.style.width = widthOf(element);
        });
    });
})();
