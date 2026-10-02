function withRequestOptions(path, evidence) {
    const url = new URL(path, 'https://work.invalid');
    const snapshot = evidence.snapshot;
    if (snapshot?.declaredPurpose) url.searchParams.set('purpose', snapshot.declaredPurpose);
    if (snapshot?.approval) url.searchParams.set('approval', snapshot.approval.approvalId || '');
    if (evidence.download?.language) url.searchParams.set('language', evidence.download.language);
    return url.pathname + url.search;
}

export function workPath(evidence) {
    const path = evidence.http.path;
    const document = /^\/api\/work\/documents\/([^/]+)\/(read|download)$/.exec(path);
    if (document) return withRequestOptions(`/${document[2] === 'download' ? 'download' : 'document'}.html?id=${encodeURIComponent(decodeURIComponent(document[1]))}`, evidence);
    const customer = /^\/api\/work\/customers\/([^/]+)\/read$/.exec(path);
    if (customer) return withRequestOptions(`/customer.html?id=${encodeURIComponent(decodeURIComponent(customer[1]))}`, evidence);
    if (path === '/api/work/exports/download') {
        const snapshot = evidence.snapshot;
        if (['DOCUMENT', 'CUSTOMER'].includes(snapshot?.resourceType) && snapshot.targets?.length) {
            const query = new URLSearchParams({ type: snapshot.resourceType });
            snapshot.targets.forEach(target => query.append('id', target.resource.id));
            return withRequestOptions(`/export.html?${query}`, evidence);
        }
        return '/customers.html';
    }
    return '/projects.html';
}
