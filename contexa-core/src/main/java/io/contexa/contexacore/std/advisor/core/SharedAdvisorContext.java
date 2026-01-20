package io.contexa.contexacore.std.advisor.core;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;


@Slf4j
public class SharedAdvisorContext {
    
    
    private final Map<String, AdvisorContext> domainContexts = new ConcurrentHashMap<>();
    
    
    private final Map<String, Object> globalContext = new ConcurrentHashMap<>();
    
    
    private final Map<String, Map<String, Object>> crossDomainData = new ConcurrentHashMap<>();
    
    
    public AdvisorContext getDomainContext(String domain) {
        return domainContexts.computeIfAbsent(domain, AdvisorContext::new);
    }
    
    
    public void setDomainContext(String domain, AdvisorContext context) {
        if (context == null) {
            throw new IllegalArgumentException("DomainContext cannot be null");
        }
        domainContexts.put(domain, context);
        log.debug("도메인 컨텍스트 설정: {}", domain);
    }
    
    
    public AdvisorContext removeDomainContext(String domain) {
        AdvisorContext removed = domainContexts.remove(domain);
        if (removed != null) {
            log.debug("도메인 컨텍스트 제거: {}", domain);
        }
        return removed;
    }
    
    
    public void setGlobal(String key, Object value) {
        globalContext.put(key, value);
        log.debug("글로벌 컨텍스트 설정: {} = {}", key, value);
    }
    
    
    public Object getGlobal(String key) {
        return globalContext.get(key);
    }
    
    
    public Object removeGlobal(String key) {
        return globalContext.remove(key);
    }
    
    
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
    
    
    @SuppressWarnings("unchecked")
    public Object getCrossDomainData(String key, String requestingDomain) {
        
        for (Map.Entry<String, Map<String, Object>> entry : crossDomainData.entrySet()) {
            if (entry.getKey().endsWith(":" + key)) {
                Map<String, Object> sharedData = entry.getValue();
                Set<String> targets = (Set<String>) sharedData.get("targets");
                
                
                
                if (targets == null || targets.contains(requestingDomain)) {
                    log.debug("크로스 도메인 데이터 접근 허용: {} for {}", key, requestingDomain);
                    return sharedData.get("value");
                }
            }
        }
        
        log.debug("크로스 도메인 데이터 접근 거부: {} for {}", key, requestingDomain);
        return null;
    }
    
    
    public void setDomainSpecific(String domain, String key, Object value) {
        AdvisorContext context = getDomainContext(domain);
        context.setAttribute(key, value);
        log.debug("도메인 특정 데이터 설정: {}:{} = {}", domain, key, value);
    }
    
    
    public Object getDomainSpecific(String domain, String key) {
        AdvisorContext context = domainContexts.get(domain);
        return context != null ? context.getAttribute(key) : null;
    }
    
    
    public void clearAll() {
        domainContexts.clear();
        globalContext.clear();
        crossDomainData.clear();
        log.info("모든 Advisor 컨텍스트 초기화");
    }
    
    
    public void clearDomain(String domain) {
        AdvisorContext context = domainContexts.get(domain);
        if (context != null) {
            context.clear();
            log.info("도메인 {} 컨텍스트 초기화", domain);
        }
    }
    
    
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
    
    
    private String generateCrossDomainKey(String sourceDomain, String key) {
        return sourceDomain + ":" + key;
    }
    
    
    public Set<String> getRegisteredDomains() {
        return domainContexts.keySet();
    }
    
    
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