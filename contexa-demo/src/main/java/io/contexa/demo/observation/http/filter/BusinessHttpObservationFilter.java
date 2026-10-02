package io.contexa.demo.observation.http.filter;

import io.contexa.demo.entry.domain.Visitor;
import io.contexa.demo.observation.health.service.CollectorRegistry;
import io.contexa.demo.observation.http.dto.BusinessHttpObservation;
import io.contexa.demo.observation.http.response.ObservedHttpResponse;
import io.contexa.demo.observation.http.service.BusinessHttpSink;
import io.contexa.demo.work.request.web.BusinessContextAttributes;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@Profile({"baseline", "contexa"})
@Order(Ordered.HIGHEST_PRECEDENCE + 21)
public class BusinessHttpObservationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(BusinessHttpObservationFilter.class);
    private final BusinessHttpSink observations;
    private final CollectorRegistry collectors;

    public BusinessHttpObservationFilter(BusinessHttpSink observations, CollectorRegistry collectors) {
        this.collectors = collectors;
        this.observations = observations;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"POST".equals(request.getMethod()) || !request.getServletPath().startsWith("/api/work/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        UUID requestId = UUID.randomUUID();
        Instant startedAt = Instant.now();
        request.setAttribute(BusinessContextAttributes.REQUEST_ID, requestId.toString());
        response.setHeader("X-Lab-Request-Id", requestId.toString());
        response.setHeader("Cache-Control", "no-store");
        String failureType = null;
        ObservedHttpResponse observedResponse = new ObservedHttpResponse(response);
        try {
            chain.doFilter(request, observedResponse);
        } catch (IOException | ServletException | RuntimeException failure) {
            failureType = failure.getClass().getSimpleName();
            throw failure;
        } finally {
            Visitor visitor = (Visitor) request.getAttribute(Visitor.class.getName());
            BusinessHttpObservation observation = new BusinessHttpObservation(requestId,
                    visitor == null ? null : visitor.id(), request.getMethod(), request.getServletPath(), startedAt,
                    Instant.now(), failureType == null ? response.getStatus() : null, failureType,
                    observedResponse.writtenBytes(request.isAsyncStarted()),
                    observedResponse.captureState(request.isAsyncStarted()), collectors.instanceId());
            try {
                observations.offer(observation);
            } catch (RuntimeException unavailable) {
                log.warn("Business HTTP observation not stored: requestId={}, reason={}", requestId,
                        unavailable.getClass().getSimpleName());
            }
        }
    }
}
