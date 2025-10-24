package io.contexa.contexacore.std.llm.core;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * LLM 연산을 위한 핵심 인터페이스
 * 
 * SOLID 원칙 적용:
 * - 단일 책임: LLM과의 통신만 담당
 * - 인터페이스 분리: 최소한의 필수 메서드만 정의
 * - 의존성 역전: 구체적인 구현이 아닌 추상화에 의존
 */
public interface LLMOperations {
    
    /**
     * LLM 실행 - 단일 응답
     * 
     * @param context 실행 컨텍스트 (모델, 태스크, 옵션 등 포함)
     * @return 응답 문자열
     */
    Mono<String> execute(ExecutionContext context);
    
    /**
     * LLM 스트리밍 실행
     * 
     * @param context 실행 컨텍스트
     * @return 스트리밍 응답
     */
    Flux<String> stream(ExecutionContext context);
    
    /**
     * 구조화된 응답 실행
     * 
     * @param context 실행 컨텍스트
     * @param targetType 변환할 타겟 클래스
     * @return 구조화된 객체
     */
    <T> Mono<T> executeEntity(ExecutionContext context, Class<T> targetType);
}