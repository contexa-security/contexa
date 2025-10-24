package io.contexa.contexacore.std.advisor.core;

import org.springframework.ai.chat.client.ChatClientRequest;

/**
 * 도메인별 정책 인터페이스
 * 
 * 각 도메인에서 적용할 정책을 정의합니다.
 */
public interface DomainPolicy {
    
    /**
     * 정책 이름
     */
    String getName();
    
    /**
     * 정책 활성화 여부
     */
    boolean isEnabled();
    
    /**
     * 정책 적용
     * 
     * @param request 원본 요청
     * @return 정책이 적용된 요청
     */
    ChatClientRequest apply(ChatClientRequest request);
    
    /**
     * 정책 검증
     * 
     * @param request 검증할 요청
     * @return 정책을 만족하면 true
     */
    boolean validate(ChatClientRequest request);
    
    /**
     * 정책 설명
     */
    String getDescription();
}