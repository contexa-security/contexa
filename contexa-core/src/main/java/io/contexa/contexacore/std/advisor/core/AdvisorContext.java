package io.contexa.contexacore.std.advisor.core;

import lombok.Getter;
import lombok.Setter;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Getter
@Setter
public class AdvisorContext {
    
    private final String domain;
    private final Map<String, Object> attributes;
    private final AtomicLong callCount;
    private final List<Map<String, Object>> crossDomainMessages;
    
    private ChatClientRequest lastRequest;
    private ChatClientResponse lastResponse;
    private long lastAccessTime;
    private String currentUser;
    private String sessionId;
    
    public AdvisorContext(String domain) {
        this.domain = domain;
        this.attributes = new ConcurrentHashMap<>();
        this.callCount = new AtomicLong(0);
        this.crossDomainMessages = new ArrayList<>();
        this.lastAccessTime = System.currentTimeMillis();
    }

    public void setAttribute(String key, Object value) {
        attributes.put(key, value);
    }

    public Object getAttribute(String key) {
        return attributes.get(key);
    }

    public Object removeAttribute(String key) {
        return attributes.remove(key);
    }

    public long incrementCallCount() {
        return callCount.incrementAndGet();
    }

    public long getCallCount() {
        return callCount.get();
    }

    public void addCrossDomainMessage(Map<String, Object> message) {
        crossDomainMessages.add(message);

        if (crossDomainMessages.size() > 100) {
            crossDomainMessages.remove(0);
        }
    }

    public void clear() {
        attributes.clear();
        crossDomainMessages.clear();
        lastRequest = null;
        lastResponse = null;
        currentUser = null;
        sessionId = null;
    }

    public AdvisorContext copy() {
        AdvisorContext copy = new AdvisorContext(domain);
        copy.attributes.putAll(this.attributes);
        copy.crossDomainMessages.addAll(this.crossDomainMessages);
        copy.lastRequest = this.lastRequest;
        copy.lastResponse = this.lastResponse;
        copy.lastAccessTime = this.lastAccessTime;
        copy.currentUser = this.currentUser;
        copy.sessionId = this.sessionId;
        return copy;
    }
    
    @Override
    public String toString() {
        return String.format("DomainContext[domain=%s, callCount=%d, attributes=%d]", 
            domain, callCount.get(), attributes.size());
    }
}