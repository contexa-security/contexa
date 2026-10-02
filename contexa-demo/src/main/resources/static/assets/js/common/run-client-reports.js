import { request } from './http.js';

const key = 'lab.run.pendingReports';
let pending;
try { pending = JSON.parse(sessionStorage.getItem(key) || '[]'); } catch { pending = []; }
if (!Array.isArray(pending)) pending = [];
pending = pending.filter(value => value && typeof value.runId === 'string' && value.observation
    && typeof value.observation.attemptId === 'string' && ['STARTED', 'FINISHED'].includes(value.observation.stage)).slice(0, 64);
const sending = new Map();
let storageAvailable = true;
function changed() {
    try { sessionStorage.setItem(key, JSON.stringify(pending)); storageAvailable = true; }
    catch { storageAvailable = false; }
    document.dispatchEvent(new CustomEvent('lab:run-reports'));
}
const same = (left, right) => left.runId === right.runId
    && left.observation.attemptId === right.observation.attemptId
    && left.observation.stage === right.observation.stage;
async function send(entry) {
    const id = `${entry.runId}:${entry.observation.attemptId}:${entry.observation.stage}`;
    if (sending.has(id)) return sending.get(id);
    const delivery = (async () => {
        try {
            await request(`/api/lab/runs/${encodeURIComponent(entry.runId)}/client-reports`, {
                method: 'POST', body: entry.observation
            });
            pending = pending.filter(value => !same(value, entry));
        } catch { /* Keep this exact report. Never retry business requests here. */ }
        finally { sending.delete(id); changed(); }
    })();
    sending.set(id, delivery);
    return delivery;
}
export function reportRunAttempt(runId, observation) {
    const entry = { runId, observation };
    if (!pending.some(value => same(value, entry))) pending.push(entry);
    changed();
    return send(entry);
}
export function pendingRunReports(runId) {
    return { count: pending.filter(value => value.runId === runId).length,
        sending: sending.size > 0, storageAvailable, capacityAvailable: pending.length <= 60 };
}
export async function retryRunReports(runId) {
    await Promise.all(pending.filter(value => value.runId === runId).map(send));
}
