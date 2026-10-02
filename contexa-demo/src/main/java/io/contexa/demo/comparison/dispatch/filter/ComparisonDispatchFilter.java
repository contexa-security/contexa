package io.contexa.demo.comparison.dispatch.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.demo.comparison.dispatch.http.PlannedBusinessRequest;
import io.contexa.demo.comparison.dispatch.service.DispatchPlanGuard;
import io.contexa.demo.comparison.run.dto.DispatchClaim;
import io.contexa.demo.comparison.run.repository.RunDispatchRepository;
import io.contexa.demo.comparison.run.repository.RunQuery;
import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.entry.domain.Visitor;
import io.contexa.demo.work.request.web.BusinessContextAttributes;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;
import java.io.IOException;
import java.util.Map;
import java.util.UUID;

@Component("comparisonDispatchFilter")
@Profile({"baseline", "contexa"})
public class ComparisonDispatchFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ComparisonDispatchFilter.class);
    private final String arm;
    private final RunQuery runs;
    private final RunDispatchRepository dispatches;
    private final DispatchPlanGuard guard;
    private final ObjectMapper mapper;

    public ComparisonDispatchFilter(LabProperties properties, RunQuery runs, RunDispatchRepository dispatches,
            DispatchPlanGuard guard, ObjectMapper mapper) {
        this.arm = properties.role();
        this.runs = runs;
        this.dispatches = dispatches;
        this.guard = guard;
        this.mapper = mapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"POST".equals(request.getMethod()) || !request.getServletPath().startsWith("/api/work/")
                || (request.getHeader("X-Lab-Run-Id") == null && request.getHeader("X-Lab-Step-Id") == null);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        DispatchClaim claim;
        byte[] body;
        try {
            Visitor visitor = (Visitor) request.getAttribute(Visitor.class.getName());
            if (visitor == null || !visitor.verified()) {
                reject(response, 403, "EMAIL_VERIFICATION_REQUIRED");
                return;
            }
            UUID runId = reference(request.getHeader("X-Lab-Run-Id"));
            UUID stepId = reference(request.getHeader("X-Lab-Step-Id"));
            var run = runs.find(visitor.id(), runId);
            if (run == null) {
                reject(response, 404, "RUN_NOT_FOUND");
                return;
            }
            try {
                body = guard.verify(run, SecurityContextHolder.getContext().getAuthentication(), request);
            } catch (ResponseStatusException rejected) {
                dispatches.reject(visitor.id(), runId, stepId, arm, rejected.getReason());
                throw rejected;
            }
            claim = dispatches.claim(visitor.id(), runId, stepId, arm, BusinessContextAttributes.requestId(request));
            if (!"DISPATCHED".equals(claim.outcome())) {
                reject(response, 409, claim.outcome());
                return;
            }
        } catch (ResponseStatusException rejected) {
            reject(response, rejected.getStatusCode().value(), rejected.getReason());
            return;
        } catch (IllegalArgumentException invalid) {
            reject(response, 400, "INVALID_COMPARISON_REFERENCE");
            return;
        }
        String failureType = null;
        try {
            chain.doFilter(new PlannedBusinessRequest(request, body), response);
        } catch (IOException | ServletException | RuntimeException failure) {
            failureType = failure.getClass().getSimpleName();
            throw failure;
        } finally {
            try {
                dispatches.respond(claim.run().id(), claim.step().id(), claim.attemptedRequestId(),
                        failureType == null ? response.getStatus() : null, failureType);
            } catch (RuntimeException unavailable) {
                log.warn("Comparison response not stored: requestId={}, reason={}",
                        claim.attemptedRequestId(), unavailable.getClass().getSimpleName());
            }
        }
    }

    private UUID reference(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Missing comparison reference");
        }
        UUID parsed = UUID.fromString(value);
        if (!parsed.toString().equalsIgnoreCase(value)) {
            throw new IllegalArgumentException("Invalid comparison reference");
        }
        return parsed;
    }

    private void reject(HttpServletResponse response, int status, String state) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        mapper.writeValue(response.getWriter(), Map.of("state", state == null ? "COMPARISON_REJECTED" : state));
    }
}
