package io.contexa.showcase.business.work;

import io.contexa.showcase.business.internal.InternalContext;
import io.contexa.showcase.business.internal.InternalContextAttributes;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Clock;
import java.time.Instant;

/**
 * Who asks for a business operation and in which run. The company time is the signed observedAt of the run, or
 * the wall clock for an unsigned request.
 *
 * @param username   sign-in name of the run principal
 * @param control    control that serves the request (A, B, C1, C2 or D)
 * @param runId      run of the principal, or null for an unsigned request
 * @param requestId  decision id assigned by the orchestrator, or null
 * @param companyTime company time of the request
 */
public record BusinessRequest(String username, String control, String runId, String requestId, Instant companyTime) {

    public static BusinessRequest of(HttpServletRequest request, String username, String control, Clock clock) {
        Object attribute = request.getAttribute(InternalContextAttributes.CONTEXT);
        if (attribute instanceof InternalContext context) {
            Instant time = context.observedAt() != null ? context.observedAt() : clock.instant();
            return new BusinessRequest(username, control, context.runId(), context.requestId(), time);
        }
        return new BusinessRequest(username, control, null, null, clock.instant());
    }
}
