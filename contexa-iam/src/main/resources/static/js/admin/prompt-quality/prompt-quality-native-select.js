(function () {
    const PQA_ROOT_SELECTOR = '.pqa-shell';

    const isInsidePqa = (element) => {
        return element && typeof element.closest === 'function' && element.closest(PQA_ROOT_SELECTOR);
    };

    const markSelect = (select) => {
        if (!select || select.tagName !== 'SELECT') {
            return;
        }
        if (!isInsidePqa(select)) {
            return;
        }
        if (!select.classList.contains('cs-skip')) {
            select.classList.add('cs-skip');
        }
        if (select.classList.contains('cs-hidden')) {
            select.classList.remove('cs-hidden');
            select.style.display = '';
        }
    };

    const unwrapInsidePqa = (wrapper) => {
        if (!wrapper || !wrapper.classList || !wrapper.classList.contains('custom-select-wrapper')) {
            return;
        }
        if (!isInsidePqa(wrapper)) {
            return;
        }
        const select = wrapper.querySelector('select');
        if (select) {
            select.classList.add('cs-skip');
            select.classList.remove('cs-hidden');
            select.style.display = '';
            select.removeAttribute('aria-hidden');
            if (wrapper.parentNode) {
                wrapper.parentNode.insertBefore(select, wrapper);
            }
        }
        wrapper.remove();
    };

    const markAllInsidePqa = () => {
        document.querySelectorAll(`${PQA_ROOT_SELECTOR} select`).forEach(markSelect);
        document.querySelectorAll(`${PQA_ROOT_SELECTOR} .custom-select-wrapper`).forEach(unwrapInsidePqa);
    };

    markAllInsidePqa();

    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (!(node instanceof Element)) {
                    return;
                }
                if (node.tagName === 'SELECT') {
                    markSelect(node);
                    return;
                }
                if (node.classList && node.classList.contains('custom-select-wrapper')) {
                    unwrapInsidePqa(node);
                    return;
                }
                if (typeof node.querySelectorAll === 'function') {
                    node.querySelectorAll('select').forEach(markSelect);
                    node.querySelectorAll('.custom-select-wrapper').forEach(unwrapInsidePqa);
                }
            });
        });
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true
    });

    const runCleanup = () => {
        markAllInsidePqa();
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', runCleanup);
    }
    else {
        runCleanup();
    }

    window.setTimeout(runCleanup, 0);
    window.setTimeout(runCleanup, 60);
    window.setTimeout(runCleanup, 250);
})();
