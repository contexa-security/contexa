package io.contexa.contexacore.std.advisor.core;

import io.opentelemetry.api.trace.Tracer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public abstract class DomainAdvisor extends BaseAdvisor {

    protected final AdvisorContext advisorContext;

    protected final Map<String, Object> domainConfig;

    protected final DomainPolicy domainPolicy;
    
    protected DomainAdvisor(Tracer tracer, String domain, String name, int order,
                          AdvisorContext advisorContext,
                          Map<String, Object> domainConfig) {
        super(tracer, domain, name, order);
        this.advisorContext = advisorContext != null ? advisorContext : new AdvisorContext(domain);
        this.domainConfig = domainConfig != null ? domainConfig : new ConcurrentHashMap<>();
        this.domainPolicy = createDomainPolicy();
    }

    protected abstract DomainPolicy createDomainPolicy();

    protected abstract boolean validateDomainRequest(ChatClientRequest request);

    protected boolean performSecurityCheck(ChatClientRequest request) {
        return true; 
    }
    
    @Override
    protected ChatClientRequest beforeCall(ChatClientRequest request) {
        
        if (!validateDomainRequest(request)) {
            throw AdvisorException.blocking(domain, name, 
                "Domain validation failed for " + domain);
        }

        if (!performSecurityCheck(request)) {
            throw AdvisorException.blocking(domain, name, 
                "Security check failed for " + domain);
        }

        updateDomainContext(request);

        return applyDomainPolicy(request);
    }
    
    @Override
    protected ChatClientResponse afterCall(ChatClientResponse response, ChatClientRequest request) {
        
        advisorContext.setLastResponse(response);
        advisorContext.incrementCallCount();

        return processDomainResponse(response, request);
    }

    protected void updateDomainContext(ChatClientRequest request) {
        advisorContext.setLastRequest(request);
        advisorContext.setLastAccessTime(System.currentTimeMillis());

        request.context().put(domain + ".context", advisorContext);
    }

    protected ChatClientRequest applyDomainPolicy(ChatClientRequest request) {
        if (domainPolicy != null && domainPolicy.isEnabled()) {
                        return domainPolicy.apply(request);
        }
        return request;
    }

    protected ChatClientResponse processDomainResponse(ChatClientResponse response, 
                                                      ChatClientRequest request) {

        return response;
    }

    protected void communicateWithDomain(String targetDomain, String message, Object data) {

        Map<String, Object> crossDomainData = new ConcurrentHashMap<>();
        crossDomainData.put("source", domain);
        crossDomainData.put("target", targetDomain);
        crossDomainData.put("message", message);
        crossDomainData.put("data", data);
        crossDomainData.put("timestamp", System.currentTimeMillis());

        advisorContext.addCrossDomainMessage(crossDomainData);
    }

    public Object getConfig(String key) {
        return domainConfig.get(key);
    }

    public void setConfig(String key, Object value) {
        domainConfig.put(key, value);
            }

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