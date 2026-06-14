const DEBUG_ACTIVE = /[?&]pqaDebug=1/.test(window.location.search);

if (DEBUG_ACTIVE) {
    window.addEventListener('DOMContentLoaded', installDropdownDiagnostics);
}

function installDropdownDiagnostics() {
    console.info('[pqa-debug] diagnostics active');
    const shell = document.querySelector('.pqa-shell') || document.body;
    const forms = shell.querySelectorAll('select, input, textarea, button, a');
    console.info('[pqa-debug] interactive elements found:', forms.length);

    forms.forEach((el, index) => {
        const cs = getComputedStyle(el);
        const rect = el.getBoundingClientRect();
        const info = {
            index,
            tag: el.tagName,
            name: el.name || el.id || el.getAttribute('data-pqa-field') || el.getAttribute('data-pqa-resource-state') || '',
            disabled: el.disabled,
            hidden: el.hidden,
            pointerEvents: cs.pointerEvents,
            zIndex: cs.zIndex,
            position: cs.position,
            display: cs.display,
            visibility: cs.visibility,
            width: Math.round(rect.width),
            height: Math.round(rect.height)
        };
        if (cs.pointerEvents === 'none' || el.disabled || cs.display === 'none' || cs.visibility === 'hidden' || rect.width === 0) {
            console.warn('[pqa-debug] SUSPECT', info);
        }
        else {
            console.log('[pqa-debug]', info);
        }

        ['mousedown', 'pointerdown', 'click', 'focus', 'change'].forEach(type => {
            el.addEventListener(type, event => {
                const top = document.elementFromPoint(
                        Math.round((rect.left + rect.right) / 2),
                        Math.round((rect.top + rect.bottom) / 2)
                );
                console.log('[pqa-debug] event', {
                    type,
                    target: el.tagName,
                    name: info.name,
                    defaultPrevented: event.defaultPrevented,
                    topAtCenter: top && top.tagName + (top.className ? '.' + String(top.className).replace(/\s+/g, '.') : ''),
                    sameAsSelf: top === el
                });
            }, true);
        });
    });

    document.addEventListener('mousedown', event => {
        const stack = document.elementsFromPoint(event.clientX, event.clientY).slice(0, 6);
        console.log('[pqa-debug] click-stack', stack.map(el => `${el.tagName}${el.className ? '.' + String(el.className).replace(/\s+/g, '.') : ''}${el.id ? '#' + el.id : ''}`));
    }, true);
}
