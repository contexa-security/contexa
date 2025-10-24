package io.contexa.contexacore.std.operations;

import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
// IAMResponse import 제거됨 - 완전 범용화
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * AI Core 시스템의 핵심 운영 인터페이스
 * 제네릭을 활용하여 다양한 도메인 컨텍스트에 대해 타입 안전한 AI 작업을 제공
 * 
 * @param <T> 도메인 컨텍스트 타입
 */
public interface AICoreOperations<T extends DomainContext> {
    
    /**
     * AI 요청을 실행하고 응답을 반환합니다
     * @param request AI 요청
     * @param responseType 응답 타입
     * @return AI 응답
     */
    <R extends AIResponse> Mono<R> process(AIRequest<T> request, Class<R> responseType);
    
    /**
     * AI 요청을 스트리밍 방식으로 실행합니다
     * @param request AI 요청
     * @return 스트리밍 응답
     */
    Flux<String> processStream(AIRequest<T> request);
    
    /**
     * AI 요청을 스트리밍 방식으로 실행하고 타입 안전한 응답을 반환합니다
     * @param request AI 요청
     * @param responseType 응답 타입
     * @return 타입화된 스트리밍 응답
     */
    <R extends AIResponse> Flux<R> executeStreamTyped(AIRequest<T> request, Class<R> responseType);
    
    /**
     * 배치 요청을 처리합니다
     * @param requests 요청 목록
     * @param responseType 응답 타입
     * @return 응답 목록
     */
    <R extends AIResponse> Mono<List<R>> executeBatch(List<AIRequest<T>> requests, Class<R> responseType);
    
    /**
     * 다중 도메인 컨텍스트 요청을 처리합니다
     * @param requests1 첫 번째 타입의 요청 목록
     * @param requests2 두 번째 타입의 요청 목록
     * @return 혼합 응답
     */
    <T1 extends DomainContext, T2 extends DomainContext> 
    Mono<AIResponse> executeMixed(List<AIRequest<T1>> requests1, List<AIRequest<T2>> requests2);

}