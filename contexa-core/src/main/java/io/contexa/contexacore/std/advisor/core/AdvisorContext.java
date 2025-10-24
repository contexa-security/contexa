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

/**
 * 도메인별 컨텍스트
 * 
 * 도메인 내에서 공유되는 상태와 데이터를 관리합니다.
 */
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
    
    /**
     * 속성 설정
     */
    public void setAttribute(String key, Object value) {
        attributes.put(key, value);
    }
    
    /**
     * 속성 조회
     */
    public Object getAttribute(String key) {
        return attributes.get(key);
    }
    
    /**
     * 속성 제거
     */
    public Object removeAttribute(String key) {
        return attributes.remove(key);
    }
    
    /**
     * 호출 횟수 증가
     */
    public long incrementCallCount() {
        return callCount.incrementAndGet();
    }
    
    /**
     * 호출 횟수 조회
     */
    public long getCallCount() {
        return callCount.get();
    }
    
    /**
     * 크로스 도메인 메시지 추가
     */
    public void addCrossDomainMessage(Map<String, Object> message) {
        crossDomainMessages.add(message);
        
        // 메시지 수 제한 (최근 100개만 유지)
        if (crossDomainMessages.size() > 100) {
            crossDomainMessages.remove(0);
        }
    }
    
    /**
     * 컨텍스트 초기화
     */
    public void clear() {
        attributes.clear();
        crossDomainMessages.clear();
        lastRequest = null;
        lastResponse = null;
        currentUser = null;
        sessionId = null;
    }
    
    /**
     * 컨텍스트 복제
     */
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