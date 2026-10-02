import { request } from './http.js';

export function matchingApprovedTargets(catalogs, account, purpose) {
    const targets = catalogs.map(records => new Set(records.filter(value => value.effectiveStatus === 'APPROVED'
        && value.request.requester === account && value.request.purpose === purpose
        && value.request.resourceType === 'DOCUMENT')
        .flatMap(value => value.request.targets.map(target => `${target.id}:${target.version}`))));
    return new Set([...targets[0]].filter(value => targets[1].has(value)));
}

// This is a catalog view of server-reported approvals, not an authorization decision.
export async function readJourneyApprovals(origins, account, purpose) {
    const arms = ['baseline', 'contexa'];
    const results = await Promise.allSettled(arms.map(arm => request('/api/work/approvals', {
        origin: origins[`${arm}Url`]
    })));
    const failures = results.flatMap((result, index) => result.status === 'rejected'
        ? [{ arm: arms[index], data: result.reason?.data, status: result.reason?.status }] : []);
    return {
        targets: matchingApprovedTargets(results.map(result => result.status === 'fulfilled'
            && Array.isArray(result.value) ? result.value : []), account, purpose),
        failures
    };
}
