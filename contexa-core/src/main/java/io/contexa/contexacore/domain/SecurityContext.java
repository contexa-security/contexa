package io.contexa.contexacore.domain;

import lombok.Getter;
import lombok.Setter;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Getter
@Setter
public class SecurityContext {
    private final Map<String, Object> securityAttributes;
    private String currentUser;
    private String sessionId;
    private String sourceIp;
    private boolean authenticated;
    
    public SecurityContext() {
        this.securityAttributes = new ConcurrentHashMap<>();
        this.authenticated = false;
    }
    
    public SecurityContext(String currentUser, String sessionId) {
        this();
        this.currentUser = currentUser;
        this.sessionId = sessionId;
        this.authenticated = true;
    }
    
    public void addSecurityAttribute(String key, Object value) {
        this.securityAttributes.put(key, value);
    }
    public Object getSecurityAttribute(String key) {
        return this.securityAttributes.get(key);
    }
    public Map<String, Object> getSecurityAttributes() { return Map.copyOf(securityAttributes); }

    @Override
    public String toString() {
        return String.format("SecurityContext{user='%s', session='%s', authenticated=%s}", 
                currentUser, sessionId, authenticated);
    }
} 