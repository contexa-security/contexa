package io.contexa.contexacore.std.advisor.core;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 공유 Advisor 컨텍스트
 * 
 * 모든 도메인 간 공유되는 컨텍스트를 관리합니다.
 * - 도메인별 격리된 컨텍스트
 * - 크로스 도메인 데이터 공유
 * - 글로벌 컨텍스트 관리
 */
@Slf4j
@Component
public class SharedAdvisorContext {
    
    /**
     * 도메인별 컨텍스트
     */
    private final Map<String, AdvisorContext> domainContexts = new ConcurrentHashMap<>();
    
    /**
     * 글로벌 공유 데이터 (모든 도메인에서 접근 가능)
     */
    private final Map<String, Object> globalContext = new ConcurrentHashMap<>();
    
    /**
     * 크로스 도메인 공유 데이터
     */
    private final Map<String, Map<String, Object>> crossDomainData = new ConcurrentHashMap<>();
    
    /**
     * 도메인 컨텍스트 조회 (없으면 생성)
     */
    public AdvisorContext getDomainContext(String domain) {
        return domainContexts.computeIfAbsent(domain, AdvisorContext::new);
    }
    
    /**
     * 도메인 컨텍스트 설정
     */
    public void setDomainContext(String domain, AdvisorContext context) {
        if (context == null) {
            throw new IllegalArgumentException("DomainContext cannot be null");
        }
        domainContexts.put(domain, context);
        log.debug("도메인 컨텍스트 설정: {}", domain);
    }
    
    /**
     * 도메인 컨텍스트 제거
     */
    public AdvisorContext removeDomainContext(String domain) {
        AdvisorContext removed = domainContexts.remove(domain);
        if (removed != null) {
            log.debug("도메인 컨텍스트 제거: {}", domain);
        }
        return removed;
    }
    
    /**
     * 글로벌 데이터 설정
     */
    public void setGlobal(String key, Object value) {
        globalContext.put(key, value);
        log.debug("글로벌 컨텍스트 설정: {} = {}", key, value);
    }
    
    /**
     * 글로벌 데이터 조회
     */
    public Object getGlobal(String key) {
        return globalContext.get(key);
    }
    
    /**
     * 글로벌 데이터 제거
     */
    public Object removeGlobal(String key) {
        return globalContext.remove(key);
    }
    
    /**
     * 크로스 도메인 데이터 공유
     * 
     * @param key 공유 키
     * @param value 공유할 데이터
     * @param sourceDomain 데이터를 제공하는 도메인
     * @param targetDomains 데이터를 받을 도메인들 (null이면 모든 도메인)
     */
    public void shareAcrossDomains(String key, Object value, String sourceDomain, 
                                  Set<String> targetDomains) {
        String crossDomainKey = generateCrossDomainKey(sourceDomain, key);
        
        Map<String, Object> sharedData = new ConcurrentHashMap<>();
        sharedData.put("value", value);
        sharedData.put("source", sourceDomain);
        sharedData.put("targets", targetDomains);
        sharedData.put("timestamp", System.currentTimeMillis());
        
        crossDomainData.put(crossDomainKey, sharedData);
        
        log.debug("크로스 도메인 데이터 공유: {} from {} to {}", 
            key, sourceDomain, targetDomains != null ? targetDomains : "ALL");
    }
    
    /**
     * 크로스 도메인 데이터 조회
     * 
     * @param key 공유 키
     * @param requestingDomain 데이터를 요청하는 도메인
     * @return 공유된 데이터 (접근 권한이 없으면 null)
     */
    @SuppressWarnings("unchecked")
    public Object getCrossDomainData(String key, String requestingDomain) {
        // 모든 소스 도메인에서 해당 키 검색
        for (Map.Entry<String, Map<String, Object>> entry : crossDomainData.entrySet()) {
            if (entry.getKey().endsWith(":" + key)) {
                Map<String, Object> sharedData = entry.getValue();
                Set<String> targets = (Set<String>) sharedData.get("targets");
                
                // 타겟이 null이면 모든 도메인 허용
                // 타겟이 지정되었으면 해당 도메인만 허용
                if (targets == null || targets.contains(requestingDomain)) {
                    log.debug("크로스 도메인 데이터 접근 허용: {} for {}", key, requestingDomain);
                    return sharedData.get("value");
                }
            }
        }
        
        log.debug("크로스 도메인 데이터 접근 거부: {} for {}", key, requestingDomain);
        return null;
    }
    
    /**
     * 도메인별 격리된 데이터 설정
     */
    public void setDomainSpecific(String domain, String key, Object value) {
        AdvisorContext context = getDomainContext(domain);
        context.setAttribute(key, value);
        log.debug("도메인 특정 데이터 설정: {}:{} = {}", domain, key, value);
    }
    
    /**
     * 도메인별 격리된 데이터 조회
     */
    public Object getDomainSpecific(String domain, String key) {
        AdvisorContext context = domainContexts.get(domain);
        return context != null ? context.getAttribute(key) : null;
    }
    
    /**
     * 모든 도메인 컨텍스트 초기화
     */
    public void clearAll() {
        domainContexts.clear();
        globalContext.clear();
        crossDomainData.clear();
        log.info("모든 Advisor 컨텍스트 초기화");
    }
    
    /**
     * 특정 도메인 컨텍스트 초기화
     */
    public void clearDomain(String domain) {
        AdvisorContext context = domainContexts.get(domain);
        if (context != null) {
            context.clear();
            log.info("도메인 {} 컨텍스트 초기화", domain);
        }
    }
    
    /**
     * 컨텍스트 상태 조회
     */
    public ContextStats getStats() {
        Map<String, Long> domainCallCounts = new ConcurrentHashMap<>();
        
        for (Map.Entry<String, AdvisorContext> entry : domainContexts.entrySet()) {
            domainCallCounts.put(entry.getKey(), entry.getValue().getCallCount());
        }
        
        return new ContextStats(
            domainContexts.size(),
            globalContext.size(),
            crossDomainData.size(),
            domainCallCounts
        );
    }
    
    /**
     * 크로스 도메인 키 생성
     */
    private String generateCrossDomainKey(String sourceDomain, String key) {
        return sourceDomain + ":" + key;
    }
    
    /**
     * 등록된 모든 도메인 조회
     */
    public Set<String> getRegisteredDomains() {
        return domainContexts.keySet();
    }
    
    /**
     * 컨텍스트 통계
     */
    public static class ContextStats {
        public final int domainCount;
        public final int globalDataCount;
        public final int crossDomainDataCount;
        public final Map<String, Long> domainCallCounts;
        
        public ContextStats(int domainCount, int globalDataCount, 
                           int crossDomainDataCount, Map<String, Long> domainCallCounts) {
            this.domainCount = domainCount;
            this.globalDataCount = globalDataCount;
            this.crossDomainDataCount = crossDomainDataCount;
            this.domainCallCounts = domainCallCounts;
        }
        
        @Override
        public String toString() {
            return String.format("ContextStats[domains=%d, global=%d, crossDomain=%d]",
                domainCount, globalDataCount, crossDomainDataCount);
        }
    }
}