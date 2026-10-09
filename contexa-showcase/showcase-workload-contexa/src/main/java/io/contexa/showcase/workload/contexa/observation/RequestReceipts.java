package io.contexa.showcase.workload.contexa.observation;

import io.contexa.showcase.business.internal.InternalContextAttributes;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * When control D received each signed request, on D's own clock (fabricated-data survey #44). The portal times the
 * engine's analysis stages from this moment, so both ends of every interval come from the same clock; before, the
 * stages were timed from the portal's sending time, which differs from D's clock on another host.
 */
public class RequestReceipts extends OncePerRequestFilter {

    static final int MAX_REQUESTS = 20_000;

    private final Clock clock;
    private final Map<String, Instant> receivedAt = new LinkedHashMap<>(16, 0.75f, false) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Instant> eldest) {
            return size() > MAX_REQUESTS;
        }
    };

    public RequestReceipts(Clock clock) {
        this.clock = clock;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Object requestId = request.getAttribute(InternalContextAttributes.REQUEST_ID);
        if (requestId instanceof String id && !id.isBlank()) {
            Instant now = clock.instant();
            synchronized (receivedAt) {
                receivedAt.putIfAbsent(id, now);
            }
        }
        chain.doFilter(request, response);
    }

    public Optional<Instant> receivedAt(String requestId) {
        synchronized (receivedAt) {
            return Optional.ofNullable(receivedAt.get(requestId));
        }
    }
}
