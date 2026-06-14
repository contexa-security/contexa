const ACTIVATION_EVENTS = ['mouseenter', 'focusin'];
const MARGIN = 12;

function adjustSubmenu(item) {
    const submenu = item.querySelector(':scope > .pqa-nav-submenu');
    if (!submenu) {
        return;
    }
    submenu.style.top = '';
    submenu.style.bottom = '';
    const itemRect = item.getBoundingClientRect();
    const submenuHeight = submenu.scrollHeight;
    const viewportHeight = window.innerHeight;
    const spaceBelow = viewportHeight - itemRect.top - MARGIN;
    if (submenuHeight <= spaceBelow) {
        submenu.style.top = '0';
        return;
    }
    const spaceAbove = itemRect.bottom - MARGIN;
    if (submenuHeight <= spaceAbove) {
        submenu.style.top = 'auto';
        submenu.style.bottom = '0';
        return;
    }
    const shift = Math.max(MARGIN - itemRect.top, viewportHeight - itemRect.top - submenuHeight - MARGIN);
    submenu.style.top = `${shift}px`;
}

function bindAll() {
    document.querySelectorAll('.pqa-nav-item.has-submenu').forEach(item => {
        if (item.dataset.pqaDropdownBound === 'true') {
            return;
        }
        item.dataset.pqaDropdownBound = 'true';
        ACTIVATION_EVENTS.forEach(eventName => {
            item.addEventListener(eventName, () => adjustSubmenu(item));
        });
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bindAll);
}
else {
    bindAll();
}

window.addEventListener('resize', () => {
    document.querySelectorAll('.pqa-nav-item.has-submenu').forEach(item => {
        const submenu = item.querySelector(':scope > .pqa-nav-submenu');
        if (submenu) {
            submenu.style.top = '';
            submenu.style.bottom = '';
        }
    });
});
