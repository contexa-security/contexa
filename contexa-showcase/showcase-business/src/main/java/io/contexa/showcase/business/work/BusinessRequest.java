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
 * @param destination where an export says its documents go (docs/agent A6-R9), as the request wrote it; null when it
 *                    names none
 */
public record BusinessRequest(String username, String control, String runId, String requestId, Instant companyTime,
                              String destination) {

    /** A request that names no export destination. */
    public BusinessRequest(String username, String control, String runId, String requestId, Instant companyTime) {
        this(username, control, runId, requestId, companyTime, null);
    }

    public static BusinessRequest of(HttpServletRequest request, String username, String control, Clock clock) {
        String destination = request.getParameter(DESTINATION_PARAMETER);
        destination = destination == null || destination.isBlank() ? null : destination.trim();
        Object attribute = request.getAttribute(InternalContextAttributes.CONTEXT);
        if (attribute instanceof InternalContext context) {
            Instant time = context.observedAt() != null ? context.observedAt() : clock.instant();
            return new BusinessRequest(username, control, context.runId(), context.requestId(), time, destination);
        }
        return new BusinessRequest(username, control, null, null, clock.instant(), destination);
    }

    /** The query parameter an export names its destination in (docs/agent A6-R9). */
    public static final String DESTINATION_PARAMETER = "destination";
}
