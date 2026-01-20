package io.contexa.contexacore.std.advisor.security;

import io.opentelemetry.api.trace.Tracer;
import io.contexa.contexacore.std.advisor.core.BaseAdvisor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
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

    public SecurityContextAdvisor(Tracer tracer) {
        super(tracer, DOMAIN_NAME, ADVISOR_NAME, 50);
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
        log.debug("Security Context Advisor - 보안 컨텍스트 설정 시작");
        
        
        Authentication auth = null;
        try {
            auth = SecurityContextHolder.getContext().getAuthentication();
        } catch (Exception e) {
            log.debug("Spring Security 컨텍스트 없음: {}", e.getMessage());
        }
        
        
        HttpServletRequest httpRequest = null;
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) 
                RequestContextHolder.currentRequestAttributes();
            if (attrs != null) {
                httpRequest = attrs.getRequest();
            }
        } catch (Exception e) {
            log.debug("HTTP 요청 컨텍스트 없음 (비-웹 환경): {}", e.getMessage());
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
            request.context().put("remote.address", httpRequest.getRemoteAddr());
            request.context().put("request.method", httpRequest.getMethod());
            request.context().put("request.uri", httpRequest.getRequestURI());
        }
        
        log.info("보안 컨텍스트 설정 완료: userId={}, sessionId={}, authenticated={}", 
            userId, sessionId, isAuthenticated);
        
        
        if (requireAuthentication && !isAuthenticated) {
            log.warn("인증되지 않은 요청 - 인증이 필요합니다");
            
        }
        
        
        recordMetric("security.context.set", 1);
        if (isAuthenticated) {
            recordMetric("security.authenticated.requests", 1);
        } else {
            recordMetric("security.anonymous.requests", 1);
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
                return apiUser;
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
                log.debug("세션 ID 추출 실패: {}", e.getMessage());
            }
            
            
            String apiSession = request.getHeader("X-Session-Id");
            if (apiSession != null && !apiSession.isEmpty()) {
                return apiSession;
            }
        }
        
        
        return "session-" + UUID.randomUUID().toString();
    }
    
    @Override
    protected ChatClientResponse afterCall(ChatClientResponse response, ChatClientRequest request) {
        
        String userId = (String) request.context().get("user.id");
        String sessionId = (String) request.context().get("session.id");
        
        log.debug("Security Context Advisor - 요청 완료: userId={}, sessionId={}", 
            userId, sessionId);
        
        
        return response;
    }
}