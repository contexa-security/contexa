import { request, ApiError } from './http.js';
import { reportRunAttempt } from './run-client-reports.js';

export async function dispatchStep(run, step, origin) {
    const startedAt = new Date().toISOString();
    const observation = { attemptId: crypto.randomUUID(), stepId: step.id, stage: 'STARTED',
        phase: 'PREPARATION', outcome: 'UNCONFIRMED', startedAt, observedAt: startedAt,
        httpStatus: null, responseBytes: null };
    void reportRunAttempt(run.id, { ...observation });
    const result = { received: false };
    try {
        const csrf = await request('/api/auth/csrf', { origin });
        observation.phase = 'BUSINESS';
        const file = run.manifest.plan.fileRequest;
        const selection = run.manifest.plan.exportSelection;
        const approvals = selection || run.manifest.plan.approvalReferences;
        const approvalId = approvals ? approvals[step.arm === 'baseline' ? 'baselineApprovalId' : 'contexaApprovalId'] : null;
        const response = await fetch(new URL(run.manifest.plan.path, origin), {
            method: 'POST', credentials: 'include', cache: 'no-store', redirect: 'error',
            headers: { Accept: file ? 'text/plain, application/json' : 'application/json', 'Content-Type': 'application/json', [csrf.headerName]: csrf.token,
                'X-Lab-Run-Id': run.id, 'X-Lab-Step-Id': step.id },
            body: JSON.stringify({ purpose: run.manifest.plan.purpose, approvalId,
                ...(selection ? { resourceType: selection.resourceType, targetIds: selection.targetIds } : {}),
                ...(file ? { commandId: file.commandId, language: file.language } : {}) }),
            signal: AbortSignal.timeout(60000)
        });
        result.status = response.status;
        result.requestId = response.headers.get('X-Lab-Request-Id');
        observation.httpStatus = response.status;
        observation.responseBytes = 0;
        const reader = response.body?.getReader();
        if (reader) for (;;) {
            const chunk = await reader.read();
            if (chunk.done) break;
            observation.responseBytes += chunk.value.byteLength;
            if (observation.responseBytes > 1048576) {
                observation.outcome = 'RESPONSE_LIMIT';
                await reader.cancel();
                throw new Error('RESPONSE_CAPTURE_LIMIT');
            }
        }
        result.received = true;
        observation.outcome = 'RESPONSE_RECEIVED';
    } catch (error) {
        result.failure = error.name;
        if (observation.phase === 'PREPARATION') {
            observation.outcome = 'PREPARATION_FAILED';
            if (error instanceof ApiError) observation.httpStatus = error.status;
        } else if (observation.outcome !== 'RESPONSE_LIMIT') {
            observation.outcome = error.name === 'TimeoutError' || error.name === 'AbortError'
                ? 'TIMED_OUT' : 'NETWORK_FAILED';
        }
    } finally {
        observation.stage = 'FINISHED';
        observation.observedAt = new Date().toISOString();
        result.observation = { ...observation };
        await reportRunAttempt(run.id, { ...observation });
    }
    return result;
}
