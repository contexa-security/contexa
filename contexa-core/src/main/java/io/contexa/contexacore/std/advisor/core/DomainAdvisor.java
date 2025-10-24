package io.contexa.contexacore.std.advisor.core;

import io.opentelemetry.api.trace.Tracer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 도메인별 Advisor 추상 클래스
 * 
 * 특정 도메인에 속하는 Advisor들의 공통 기능을 제공합니다.
 * - 도메인 컨텍스트 관리
 * - 도메인별 정책 적용
 * - 크로스 도메인 통신
 */
@Slf4j
public abstract class DomainAdvisor extends BaseAdvisor {
    
    /**
     * 도메인별 컨텍스트 (도메인 내에서 공유되는 데이터)
     */
    protected final AdvisorContext advisorContext;
    
    /**
     * 도메인별 설정
     */
    protected final Map<String, Object> domainConfig;
    
    /**
     * 도메인별 정책
     */
    protected final DomainPolicy domainPolicy;
    
    protected DomainAdvisor(Tracer tracer, String domain, String name, int order,
                          AdvisorContext advisorContext,
                          Map<String, Object> domainConfig) {
        super(tracer, domain, name, order);
        this.advisorContext = advisorContext != null ? advisorContext : new AdvisorContext(domain);
        this.domainConfig = domainConfig != null ? domainConfig : new ConcurrentHashMap<>();
        this.domainPolicy = createDomainPolicy();
    }
    
    /**
     * 도메인별 정책 생성 (서브클래스에서 구현)
     */
    protected abstract DomainPolicy createDomainPolicy();
    
    /**
     * 도메인별 검증 로직 (서브클래스에서 구현)
     */
    protected abstract boolean validateDomainRequest(ChatClientRequest request);
    
    /**
     * 도메인별 보안 체크 (서브클래스에서 선택적 구현)
     */
    protected boolean performSecurityCheck(ChatClientRequest request) {
        return true; // 기본적으로 통과
    }
    
    @Override
    protected ChatClientRequest beforeCall(ChatClientRequest request) {
        // 도메인별 검증
        if (!validateDomainRequest(request)) {
            throw AdvisorException.blocking(domain, name, 
                "Domain validation failed for " + domain);
        }
        
        // 도메인별 보안 체크
        if (!performSecurityCheck(request)) {
            throw AdvisorException.blocking(domain, name, 
                "Security check failed for " + domain);
        }
        
        // 도메인 컨텍스트 업데이트
        updateDomainContext(request);
        
        // 도메인별 정책 적용
        return applyDomainPolicy(request);
    }
    
    @Override
    protected ChatClientResponse afterCall(ChatClientResponse response, ChatClientRequest request) {
        // 도메인 컨텍스트에 응답 정보 저장
        advisorContext.setLastResponse(response);
        advisorContext.incrementCallCount();
        
        // 도메인별 후처리
        return processDomainResponse(response, request);
    }
    
    /**
     * 도메인 컨텍스트 업데이트
     */
    protected void updateDomainContext(ChatClientRequest request) {
        advisorContext.setLastRequest(request);
        advisorContext.setLastAccessTime(System.currentTimeMillis());
        
        // 요청 컨텍스트에 도메인 컨텍스트 추가
        request.context().put(domain + ".context", advisorContext);
    }
    
    /**
     * 도메인 정책 적용
     */
    protected ChatClientRequest applyDomainPolicy(ChatClientRequest request) {
        if (domainPolicy != null && domainPolicy.isEnabled()) {
            log.debug("Applying domain policy for {}", domain);
            return domainPolicy.apply(request);
        }
        return request;
    }
    
    /**
     * 도메인별 응답 처리
     */
    protected ChatClientResponse processDomainResponse(ChatClientResponse response, 
                                                      ChatClientRequest request) {
        // 기본 구현은 응답을 그대로 반환
        // 서브클래스에서 필요시 오버라이드
        return response;
    }
    
    /**
     * 다른 도메인과의 통신
     */
    protected void communicateWithDomain(String targetDomain, String message, Object data) {
        log.debug("Cross-domain communication from {} to {}: {}", 
            domain, targetDomain, message);
        
        // SharedAdvisorContext를 통한 도메인 간 통신
        // 실제 구현은 SharedAdvisorContext 클래스에서 처리
        Map<String, Object> crossDomainData = new ConcurrentHashMap<>();
        crossDomainData.put("source", domain);
        crossDomainData.put("target", targetDomain);
        crossDomainData.put("message", message);
        crossDomainData.put("data", data);
        crossDomainData.put("timestamp", System.currentTimeMillis());
        
        // 컨텍스트에 저장
        advisorContext.addCrossDomainMessage(crossDomainData);
    }
    
    /**
     * 도메인 설정 조회
     */
    public Object getConfig(String key) {
        return domainConfig.get(key);
    }
    
    /**
     * 도메인 설정 업데이트
     */
    public void setConfig(String key, Object value) {
        domainConfig.put(key, value);
        log.debug("Domain config updated for {}: {} = {}", domain, key, value);
    }
    
    /**
     * 도메인 상태 조회
     */
    public DomainStatus getDomainStatus() {
        return new DomainStatus(
            domain,
            getName(),
            isEnabled(),
            advisorContext.getCallCount(),
            advisorContext.getLastAccessTime(),
            getMetrics()
        );
    }
    
    @Override
    public boolean validate() {
        if (!super.validate()) {
            return false;
        }
        
        if (advisorContext == null) {
            log.error("DomainContext is required for domain advisor");
            return false;
        }
        
        if (domainPolicy == null) {
            log.warn("DomainPolicy is not configured for domain {}", domain);
        }
        
        return true;
    }
    
    /**
     * 도메인 상태 정보
     */
    public static class DomainStatus {
        public final String domain;
        public final String advisorName;
        public final boolean enabled;
        public final long callCount;
        public final long lastAccessTime;
        public final Map<String, Long> metrics;
        
        public DomainStatus(String domain, String advisorName, boolean enabled,
                           long callCount, long lastAccessTime, Map<String, Long> metrics) {
            this.domain = domain;
            this.advisorName = advisorName;
            this.enabled = enabled;
            this.callCount = callCount;
            this.lastAccessTime = lastAccessTime;
            this.metrics = metrics;
        }
    }
}