const storageKey = 'lab.workReturn';
const pages = new Set(['/document.html', '/customer.html', '/download.html', '/export.html']);
const purposes = new Set(['PROJECT_REVIEW', 'CUSTOMER_SUPPORT', 'CROSS_PROJECT_REVIEW', 'APPROVED_BULK_DELIVERY', 'EMERGENCY_MAINTENANCE', 'UNDECLARED']);

function workPath(value) {
    try {
        const url = new URL(value, location.origin);
        if (url.origin !== location.origin || !pages.has(url.pathname)) return null;
        if ([...url.searchParams.keys()].some(key => !['id', 'type', 'approval', 'purpose', 'language'].includes(key))) return null;
        const ids = url.searchParams.getAll('id');
        if (!ids.length || ids.length > 50 || ids.some(id => !/^[a-z0-9-]{1,128}$/.test(id))) return null;
        if (url.pathname === '/export.html' && !['DOCUMENT', 'CUSTOMER'].includes(url.searchParams.get('type'))) return null;
        if (url.pathname !== '/export.html' && ids.length !== 1) return null;
        if (url.searchParams.has('purpose') && !purposes.has(url.searchParams.get('purpose'))) return null;
        if (url.searchParams.has('language') && !['KO', 'EN'].includes(url.searchParams.get('language'))) return null;
        const approval = url.searchParams.get('approval');
        if (approval && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(approval)) return null;
        return url.pathname + url.search;
    } catch { return null; }
}

export function rememberWorkPage(username, options = {}) {
    const url = new URL(location.href);
    for (const [key, value] of Object.entries(options)) url.searchParams.set(key, value);
    const path = workPath(url.href);
    if (!path || !username) return;
    try { sessionStorage.setItem(storageKey, JSON.stringify({ username, path })); }
    catch { /* Navigation preferences do not determine access or authentication. */ }
}

export function previousWorkPage(username) {
    try {
        const saved = JSON.parse(sessionStorage.getItem(storageKey) || 'null');
        return saved?.username === username ? workPath(saved.path) : null;
    } catch { return null; }
}
