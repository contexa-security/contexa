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

/**
 * Security Context Advisor
 * 
 * ChatClientRequest에 보안 컨텍스트 정보를 자동으로 주입합니다.
 * Spring Security와 HTTP 세션 정보를 추출하여 AI 요청에 포함시킵니다.
 * 
 * 주요 역할:
 * 1. 사용자 인증 정보 추출 및 설정
 * 2. 세션 정보 추출 및 설정
 * 3. 보안 관련 메타데이터 추가
 * 4. 다른 Advisor들이 사용할 수 있는 컨텍스트 제공
 */
@Slf4j
@Component
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
        
        // Spring Security 인증 정보 추출
        Authentication auth = null;
        try {
            auth = SecurityContextHolder.getContext().getAuthentication();
        } catch (Exception e) {
            log.debug("Spring Security 컨텍스트 없음: {}", e.getMessage());
        }
        
        // HTTP 요청 컨텍스트 추출 (있는 경우)
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
        
        // 사용자 ID 설정
        String userId = extractUserId(auth, httpRequest);
        request.context().put("user.id", userId);
        
        // 세션 ID 설정
        String sessionId = extractSessionId(httpRequest);
        request.context().put("session.id", sessionId);
        
        // 추가 보안 컨텍스트
        boolean isAuthenticated = auth != null && auth.isAuthenticated();
        request.context().put("authenticated", isAuthenticated);
        request.context().put("timestamp", System.currentTimeMillis());
        
        // 인증 정보가 있으면 추가 메타데이터 설정
        if (auth != null && auth.isAuthenticated()) {
            request.context().put("authorities", auth.getAuthorities().toString());
            request.context().put("principal.type", auth.getPrincipal().getClass().getSimpleName());
        }
        
        // HTTP 요청 정보가 있으면 추가
        if (httpRequest != null) {
            request.context().put("remote.address", httpRequest.getRemoteAddr());
            request.context().put("request.method", httpRequest.getMethod());
            request.context().put("request.uri", httpRequest.getRequestURI());
        }
        
        log.info("보안 컨텍스트 설정 완료: userId={}, sessionId={}, authenticated={}", 
            userId, sessionId, isAuthenticated);
        
        // 인증 필수 옵션이 켜져있고 인증되지 않은 경우
        if (requireAuthentication && !isAuthenticated) {
            log.warn("인증되지 않은 요청 - 인증이 필요합니다");
            // 필요한 경우 예외를 던지거나 특별한 처리를 할 수 있음
        }
        
        // 메트릭 기록
        recordMetric("security.context.set", 1);
        if (isAuthenticated) {
            recordMetric("security.authenticated.requests", 1);
        } else {
            recordMetric("security.anonymous.requests", 1);
        }
        
        // Request를 그대로 반환 (super.beforeCall 호출 불필요)
        return request;
    }
    
    /**
     * 사용자 ID 추출
     */
    private String extractUserId(Authentication auth, HttpServletRequest request) {
        // 1. Spring Security 인증 정보에서 추출
        if (auth != null && auth.isAuthenticated() && 
            !auth.getName().equals("anonymousUser")) {
            return auth.getName();
        }
        
        // 2. HTTP 요청에서 추출
        if (request != null) {
            // Principal에서 추출
            if (request.getUserPrincipal() != null) {
                return request.getUserPrincipal().getName();
            }
            
            // 헤더에서 추출 (API 키 인증 등)
            String apiUser = request.getHeader("X-API-User");
            if (apiUser != null && !apiUser.isEmpty()) {
                return apiUser;
            }
        }
        
        // 3. 기본값
        return "anonymous";
    }
    
    /**
     * 세션 ID 추출
     */
    private String extractSessionId(HttpServletRequest request) {
        // 1. HTTP 세션에서 추출
        if (request != null) {
            try {
                if (request.getSession(false) != null) {
                    return request.getSession().getId();
                }
            } catch (Exception e) {
                log.debug("세션 ID 추출 실패: {}", e.getMessage());
            }
            
            // 2. 헤더에서 추출 (API 세션 등)
            String apiSession = request.getHeader("X-Session-Id");
            if (apiSession != null && !apiSession.isEmpty()) {
                return apiSession;
            }
        }
        
        // 3. 자동 생성
        return "session-" + UUID.randomUUID().toString();
    }
    
    @Override
    protected ChatClientResponse afterCall(ChatClientResponse response, ChatClientRequest request) {
        // 감사 로그 기록
        String userId = (String) request.context().get("user.id");
        String sessionId = (String) request.context().get("session.id");
        
        log.debug("Security Context Advisor - 요청 완료: userId={}, sessionId={}", 
            userId, sessionId);
        
        // Response를 그대로 반환
        return response;
    }
}