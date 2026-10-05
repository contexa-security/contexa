package io.contexa.showcase.business.internal;

import java.time.Instant;

/**
 * Synthetic context of one orchestrated run, as verified from the signed internal headers.
 *
 * @param runId        the run whose fresh principal sends the request
 * @param requestId    decision id assigned by the orchestrator; the engine stores it as request_id
 * @param observedAt   business time of the request (the company clock), not the wall clock
 * @param clientIp     client address of the synthetic employee for this run
 * @param device       User-Agent of the synthetic employee's device for this run; the workloads see it as the
 *                     request User-Agent
 * @param organization organization scope of this run, unique per run to isolate shared engine state
 * @param tenant       tenant scope of this run, unique per run for the same reason
 */
public record InternalContext(
        String runId,
        String requestId,
        Instant observedAt,
        String clientIp,
        String device,
        String organization,
        String tenant) {
}
