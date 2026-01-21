package io.contexa.contexacore.autonomous.filter;

import io.contexa.contexacore.autonomous.interceptor.ZeroTrustResponseInterceptor;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
@RequiredArgsConstructor
@Slf4j
public class ZeroTrustResponseFilter extends OncePerRequestFilter {

    private final ZeroTrustResponseInterceptor interceptor;

    public static final String REQUEST_ID_HEADER = "X-ZeroTrust-Request-Id";

    public static final String REQUEST_ID_ATTRIBUTE = "zeroTrustRequestId";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String requestId = request.getHeader(REQUEST_ID_HEADER);
        if (requestId == null || requestId.isEmpty()) {
            requestId = generateRequestId();
        }

        request.setAttribute(REQUEST_ID_ATTRIBUTE, requestId);

        response.setHeader(REQUEST_ID_HEADER, requestId);

        try {
            
            interceptor.registerResponse(requestId, response);

            filterChain.doFilter(request, response);

        } finally {
            
            interceptor.unregisterResponse(requestId);

            interceptor.clearRuntimeInterception(requestId);

                    }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        if (path.startsWith("/static/") ||
            path.startsWith("/css/") ||
            path.startsWith("/js/") ||
            path.startsWith("/images/") ||
            path.startsWith("/favicon.ico")) {
            return true;
        }

        if (path.startsWith("/actuator/") ||
            path.equals("/health") ||
            path.equals("/ready") ||
            path.equals("/live")) {
            return true;
        }

        return false;
    }

    private String generateRequestId() {
        return String.format("zt-%d-%s",
            System.currentTimeMillis(),
            UUID.randomUUID().toString().substring(0, 8));
    }

    public static String getRequestId(HttpServletRequest request) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return requestId != null ? requestId.toString() : null;
    }
}
