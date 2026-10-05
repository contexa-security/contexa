package io.contexa.showcase.business.internal;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * Applies the run context that the portal orchestrator signed. It runs before Spring Security and the engine,
 * so the engine reads the run's organization, tenant, event time, decision id, client address and device.
 * <p>
 * A request without a signature, with a wrong signature or with a stale timestamp keeps no internal context;
 * the latter two are logged. Every request, signed or not, has the internal and untrusted client headers hidden.
 */
public class InternalContextFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(InternalContextFilter.class);

    private final InternalContextSigner signer;
    private final Clock clock;
    private final Duration maxClockSkew;

    public InternalContextFilter(InternalContextSigner signer, Clock clock, Duration maxClockSkew) {
        this.signer = signer;
        this.clock = clock;
        this.maxClockSkew = maxClockSkew;
    }

    /** Path covered by the signature: the request URI plus the query string when present. */
    public static String signedPath(String requestUri, String queryString) {
        return queryString == null || queryString.isEmpty() ? requestUri : requestUri + "?" + queryString;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        InternalContext context = verifiedContext(request);
        if (context != null) {
            request.setAttribute(InternalContextAttributes.CONTEXT, context);
            setIfPresent(request, InternalContextAttributes.OBSERVED_AT, context.observedAt());
            setIfPresent(request, InternalContextAttributes.ORGANIZATION_ID, context.organization());
            setIfPresent(request, InternalContextAttributes.TENANT_ID, context.tenant());
            setIfPresent(request, InternalContextAttributes.REQUEST_ID, context.requestId());
        }
        chain.doFilter(new InternalContextRequest(request, context), response);
    }

    private InternalContext verifiedContext(HttpServletRequest request) {
        String signature = request.getHeader(InternalContextHeaders.SIGNATURE);
        if (signature == null) {
            return null;
        }
        String path = signedPath(request.getRequestURI(), request.getQueryString());
        try {
            long timestamp = Long.parseLong(request.getHeader(InternalContextHeaders.TIMESTAMP));
            long skewSeconds = Math.abs(clock.instant().getEpochSecond() - timestamp);
            if (skewSeconds > maxClockSkew.toSeconds()) {
                log.error("Ignored internal context with a stale timestamp: path={}, skewSeconds={}", path, skewSeconds);
                return null;
            }
            String observedAt = request.getHeader(InternalContextHeaders.OBSERVED_AT);
            InternalContext context = new InternalContext(
                    request.getHeader(InternalContextHeaders.RUN),
                    request.getHeader(InternalContextHeaders.REQUEST_ID),
                    observedAt == null || observedAt.isBlank() ? null : Instant.parse(observedAt),
                    request.getHeader(InternalContextHeaders.CLIENT_IP),
                    request.getHeader(InternalContextHeaders.DEVICE),
                    request.getHeader(InternalContextHeaders.ORGANIZATION),
                    request.getHeader(InternalContextHeaders.TENANT));
            if (!signer.verify(request.getMethod(), path, timestamp, context, signature)) {
                log.error("Ignored internal context with an invalid signature: path={}", path);
                return null;
            }
            return context;
        } catch (NumberFormatException | DateTimeParseException e) {
            log.error("Ignored malformed internal context: path={}", path, e);
            return null;
        }
    }

    private static void setIfPresent(HttpServletRequest request, String name, Object value) {
        if (value instanceof String text && text.isBlank()) {
            return;
        }
        if (value != null) {
            request.setAttribute(name, value);
        }
    }
}
