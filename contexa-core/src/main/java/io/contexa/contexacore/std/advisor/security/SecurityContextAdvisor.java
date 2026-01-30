package io.contexa.contexacore.std.advisor.security;

import io.contexa.contexacore.std.advisor.core.AdvisorException;
import io.contexa.contexacore.std.advisor.core.BaseAdvisor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

import java.util.UUID;

@Slf4j
public class SecurityContextAdvisor extends BaseAdvisor {

    private static final String DOMAIN_NAME = "SECURITY";
    private static final String ADVISOR_NAME = "security-context";

    @Value("${contexa.advisor.security.order:50}")
    private int advisorOrder;

    @Value("${contexa.advisor.security.enabled:true}")
    private boolean advisorEnabled;

    @Value("${contexa.advisor.security.require-authentication:false}")
    private boolean requireAuthentication;

    public SecurityContextAdvisor() {
        super(DOMAIN_NAME, ADVISOR_NAME, 50);
    }

    @Override
    public int getOrder() {
        return advisorOrder;
    }

    @Override
    public boolean isEnabled() {
        return advisorEnabled;
    }

    @Override
    protected ChatClientRequest beforeCall(ChatClientRequest request) {

        Authentication auth = null;
        try {
            auth = SecurityContextHolder.getContext().getAuthentication();
        } catch (Exception e) {
            log.error("Failed to get SecurityContext authentication", e);
        }

        HttpServletRequest httpRequest = null;
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes)
                    RequestContextHolder.currentRequestAttributes();
            if (attrs != null) {
                httpRequest = attrs.getRequest();
            }
        } catch (Exception e) {
            log.error("Failed to get HttpServletRequest from RequestContext", e);
        }

        String userId = extractUserId(auth, httpRequest);
        request.context().put("user.id", userId);

        String sessionId = extractSessionId(httpRequest);
        request.context().put("session.id", sessionId);

        boolean isAuthenticated = auth != null && auth.isAuthenticated();
        request.context().put("authenticated", isAuthenticated);
        request.context().put("timestamp", System.currentTimeMillis());

        if (auth != null && auth.isAuthenticated()) {
            request.context().put("authorities", auth.getAuthorities().toString());
            request.context().put("principal.type", auth.getPrincipal().getClass().getSimpleName());
        }

        if (httpRequest != null) {
            String remoteAddr = extractTrustedRemoteAddress(httpRequest);
            request.context().put("remote.address", remoteAddr);
            request.context().put("request.method", httpRequest.getMethod());
            request.context().put("request.uri", httpRequest.getRequestURI());
            request.context().put("request.start.time", System.currentTimeMillis());
        }

        if (requireAuthentication && !isAuthenticated) {
            log.error("Authentication required but request is not authenticated");
            throw AdvisorException.blocking(DOMAIN_NAME, ADVISOR_NAME, "Authentication required");
        }
        return request;
    }

    private String extractUserId(Authentication auth, HttpServletRequest request) {

        if (auth != null && auth.isAuthenticated() &&
                !auth.getName().equals("anonymousUser")) {
            return auth.getName();
        }

        if (request != null) {

            if (request.getUserPrincipal() != null) {
                return request.getUserPrincipal().getName();
            }

            String apiUser = request.getHeader("X-API-User");
            if (apiUser != null && !apiUser.isEmpty()) {
                log.error("X-API-User header is not trusted without authentication. Ignoring header value: {}", apiUser);
            }
        }

        return "anonymous";
    }

    private String extractSessionId(HttpServletRequest request) {

        if (request != null) {
            try {
                if (request.getSession(false) != null) {
                    return request.getSession().getId();
                }
            } catch (Exception e) {
                log.error("Failed to get session ID from HttpServletRequest", e);
            }

            String apiSession = request.getHeader("X-Session-Id");
            if (apiSession != null && !apiSession.isEmpty()) {
                log.error("X-Session-Id header is not trusted. Ignoring untrusted session ID: {}", apiSession);
            }
        }

        return "session-" + UUID.randomUUID().toString();
    }

    private String extractTrustedRemoteAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            log.error("X-Forwarded-For header detected but not trusted: {}. Using direct connection address.", xForwardedFor);
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            log.error("X-Real-IP header detected but not trusted: {}. Using direct connection address.", xRealIp);
        }

        return request.getRemoteAddr();
    }

    @Override
    protected ChatClientResponse afterCall(ChatClientResponse response, ChatClientRequest request) {
        Object userId = request.context().get("user.id");
        Object sessionId = request.context().get("session.id");
        Object authenticated = request.context().get("authenticated");
        Object remoteAddr = request.context().get("remote.address");
        Object requestUri = request.context().get("request.uri");
        Object startTime = request.context().get("request.start.time");

        long executionTime = 0;
        if (startTime instanceof Long) {
            executionTime = System.currentTimeMillis() - (Long) startTime;
        }

        boolean hasResponse = response != null && response.chatResponse() != null;

        log.error("LLM audit - userId: {}, sessionId: {}, authenticated: {}, remoteAddr: {}, uri: {}, executionTimeMs: {}, hasResponse: {}",
                userId, sessionId, authenticated, remoteAddr, requestUri, executionTime, hasResponse);

        return response;
    }
}