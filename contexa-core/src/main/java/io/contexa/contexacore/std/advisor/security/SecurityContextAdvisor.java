package io.contexa.contexacore.std.advisor.security;

import io.contexa.contexacore.security.async.AsyncAuthenticationData;
import io.contexa.contexacore.security.async.AsyncSecurityContextProvider;
import io.contexa.contexacore.std.advisor.core.AdvisorException;
import io.contexa.contexacore.std.advisor.core.BaseAdvisor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.Optional;
import java.util.UUID;

@Slf4j
public class SecurityContextAdvisor extends BaseAdvisor {

    private static final String DOMAIN_NAME = "SECURITY";
    private static final String ADVISOR_NAME = "security-context";

    @Autowired(required = false)
    private AsyncSecurityContextProvider asyncSecurityContextProvider;

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
        Object eventUserIdObj = request.context().get("event.userId");
        String eventUserId = (eventUserIdObj instanceof String) ? (String) eventUserIdObj : null;

        Object eventSessionIdObj = request.context().get("event.sessionId");
        String eventSessionId = (eventSessionIdObj instanceof String) ? (String) eventSessionIdObj : null;

        Optional<AsyncAuthenticationData> asyncAuth = Optional.empty();
        if (asyncSecurityContextProvider != null && eventUserId != null && !eventUserId.isEmpty()) {
            try {
                asyncAuth = asyncSecurityContextProvider.getCurrentAuthentication(eventUserId);
            } catch (Exception e) {
                log.error("Failed to get async authentication data from Redis for userId: {}", eventUserId, e);
            }
        }

        if (asyncAuth.isPresent()) {
            AsyncAuthenticationData authData = asyncAuth.get();
            request.context().put("user.id", authData.getUserId());
            request.context().put("session.id", authData.getSessionId() != null
                    ? authData.getSessionId()
                    : (eventSessionId != null ? eventSessionId : "async-" + UUID.randomUUID()));
            request.context().put("authenticated", true);
            request.context().put("authorities", authData.getAuthorities() != null
                    ? authData.getAuthorities().toString()
                    : "[]");
            request.context().put("principal.type", authData.getPrincipalType() != null
                    ? authData.getPrincipalType()
                    : "AsyncPrincipal");
        } else {
            request.context().put("user.id", eventUserId != null ? eventUserId : "anonymous");
            request.context().put("session.id", eventSessionId != null
                    ? eventSessionId
                    : "async-" + UUID.randomUUID());
            request.context().put("authenticated", eventUserId != null && !eventUserId.isEmpty());
        }

        request.context().put("async.context", true);
        request.context().put("timestamp", System.currentTimeMillis());

        boolean isAuthenticated = asyncAuth.isPresent() || (eventUserId != null && !eventUserId.isEmpty());
        if (requireAuthentication && !isAuthenticated) {
            log.error("Authentication required but request has no authentication context");
            throw AdvisorException.blocking(DOMAIN_NAME, ADVISOR_NAME, "Authentication required");
        }

        return request;
    }

    @Override
    protected ChatClientResponse afterCall(ChatClientResponse response, ChatClientRequest request) {
        Object userId = request.context().get("user.id");
        Object sessionId = request.context().get("session.id");
        Object authenticated = request.context().get("authenticated");
        Object startTime = request.context().get("timestamp");

        long executionTime = 0;
        if (startTime instanceof Long) {
            executionTime = System.currentTimeMillis() - (Long) startTime;
        }

        boolean hasResponse = response != null && response.chatResponse() != null;

        log.error("LLM audit - userId: {}, sessionId: {}, authenticated: {}, executionTimeMs: {}, hasResponse: {}",
                userId, sessionId, authenticated, executionTime, hasResponse);

        return response;
    }
}
