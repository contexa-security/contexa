/**
 * Custom Select Dropdown - Global auto-replacement for native <select> elements.
 * Syncs value to hidden native <select> so forms submit correctly.
 */
(function() {
    function initCustomSelects() {
        document.querySelectorAll('select:not(.cs-hidden):not(.cs-skip)').forEach(function(sel) {
            if (sel.closest('.custom-select-wrapper')) return;
            // Skip selects that already have custom wrappers (e.g. modern-select-wrapper)
            if (sel.closest('.modern-select-wrapper') || sel.closest('.searchable-select-wrapper')) return;

            var wrapper = document.createElement('div');
            wrapper.className = 'custom-select-wrapper';

            var trigger = document.createElement('div');
            trigger.className = 'custom-select-trigger';
            trigger.setAttribute('tabindex', '0');

            var label = document.createElement('span');
            label.className = 'cs-label';

            var arrow = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            arrow.setAttribute('class', 'cs-arrow');
            arrow.setAttribute('viewBox', '0 0 20 20');
            arrow.setAttribute('fill', 'currentColor');
            var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            path.setAttribute('fill-rule', 'evenodd');
            path.setAttribute('d', 'M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z');
            path.setAttribute('clip-rule', 'evenodd');
            arrow.appendChild(path);

            trigger.appendChild(label);
            trigger.appendChild(arrow);

            var optionsPanel = document.createElement('div');
            optionsPanel.className = 'custom-select-options';

            // Build options from native select
            var options = sel.querySelectorAll('option');
            options.forEach(function(opt) {
                var div = document.createElement('div');
                div.className = 'custom-select-option';
                div.setAttribute('data-value', opt.value);
                div.textContent = opt.textContent;

                if (opt.selected) {
                    div.classList.add('selected');
                }

                div.addEventListener('click', function(e) {
                    e.stopPropagation();
                    // Update native select
                    sel.value = opt.value;
                    sel.dispatchEvent(new Event('change', { bubbles: true }));

                    // Update UI
                    optionsPanel.querySelectorAll('.custom-select-option').forEach(function(o) {
                        o.classList.remove('selected');
                    });
                    div.classList.add('selected');

                    if (opt.value === '') {
                        label.textContent = opt.textContent;
                        label.classList.add('cs-placeholder');
                    } else {
                        label.textContent = opt.textContent;
                        label.classList.remove('cs-placeholder');
                    }

                    close();
                });

                optionsPanel.appendChild(div);
            });

            // Set initial label
            var selectedOpt = sel.options[sel.selectedIndex];
            if (selectedOpt) {
                label.textContent = selectedOpt.textContent;
                if (selectedOpt.value === '') {
                    label.classList.add('cs-placeholder');
                }
            }

            // Insert into DOM
            sel.parentNode.insertBefore(wrapper, sel);
            wrapper.appendChild(trigger);
            wrapper.appendChild(optionsPanel);
            wrapper.appendChild(sel);
            sel.classList.add('cs-hidden');

            // Toggle
            function toggle() {
                var isOpen = optionsPanel.classList.contains('open');
                closeAll();
                if (!isOpen) {
                    optionsPanel.classList.add('open');
                    trigger.classList.add('open');
                }
            }

            function close() {
                optionsPanel.classList.remove('open');
                trigger.classList.remove('open');
            }

            trigger.addEventListener('click', function(e) {
                e.stopPropagation();
                toggle();
            });

            trigger.addEventListener('keydown', function(e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    toggle();
                } else if (e.key === 'Escape') {
                    close();
                }
            });
        });
    }

    function closeAll() {
        document.querySelectorAll('.custom-select-options.open').forEach(function(p) {
            p.classList.remove('open');
        });
        document.querySelectorAll('.custom-select-trigger.open').forEach(function(t) {
            t.classList.remove('open');
        });
    }

    // Close on outside click
    document.addEventListener('click', function() {
        closeAll();
    });

    // Init on DOMContentLoaded
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initCustomSelects);
    } else {
        initCustomSelects();
    }

    // Expose for dynamic content
    window.initCustomSelects = initCustomSelects;
})();
