// Presentation of a declared scenario against the actual catalog. The server still owns authorization.
export function selectJourneyRecords(records, projects, selector, approvedTargets = new Set()) {
    const assigned = new Set(projects.filter(project => project.assigned).map(project => project.id));
    if (selector === 'DOCUMENT_WITH_UNTRUSTED_INSTRUCTION') return records.filter(record => record.id === 'harbor-external-note');
    if (selector?.includes('UNASSIGNED')) return records.filter(record => !assigned.has(record.projectId));
    if (selector === 'ASSIGNED_PROJECT_DOCUMENTS') return records.filter(record => assigned.has(record.projectId));
    if (['EXCEPTION_APPROVED_DOCUMENTS', 'APPROVED_PROJECT_DOCUMENTS'].includes(selector)) {
        return records.filter(record => approvedTargets.has(`${record.id}:${record.version}`));
    }
    return records;
}
