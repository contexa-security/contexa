package io.contexa.contexacore.std.pipeline.executor;

import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * 범용 파이프라인 실행자 인터페이스
 * 
 * SRP: 파이프라인 실행만 담당
 * OCP: 도메인별 특화 구현 가능
 * 
 * 구현체:
 * - UniversalPipelineExecutor: 범용 처리
 * - IAMPipelineExecutor: IAM 도메인 특화
 * - 기타 도메인별 Executor 확장 가능
 */
public interface PipelineExecutor {
    
    /**
     * 완전한 파이프라인 실행 (6단계 모두 처리)
     * 
     * @param request AI 요청
     * @param configuration 파이프라인 설정
     * @param responseType 응답 타입
     * @return 처리된 AI 응답
     */
    <T extends DomainContext, R extends AIResponse> Mono<R> execute(
            AIRequest<T> request,
            PipelineConfiguration<T> configuration,
            Class<R> responseType);
    
    /**
     * 스트리밍 파이프라인 실행 (실시간 응답)
     * 
     * @param request AI 요청
     * @param configuration 파이프라인 설정
     * @return 스트리밍 응답
     */
    <T extends DomainContext> Flux<String> executeStream(
            AIRequest<T> request, 
            PipelineConfiguration<T> configuration);
    
    /**
     * 지원하는 도메인 반환
     * 
     * @return 도메인 식별자 (예: "IAM", "UNIVERSAL")
     */
    String getSupportedDomain();
    
    /**
     * 설정 지원 여부 확인
     * 
     * @param configuration 파이프라인 설정
     * @return 지원 여부
     */
    <T extends DomainContext> boolean supportsConfiguration(PipelineConfiguration<T> configuration);
    
    /**
     * 실행자 우선순위 (낮은 값이 높은 우선순위)
     * 도메인별 특화 Executor가 범용 Executor보다 우선
     */
    default int getPriority() {
        return 100; // 기본 우선순위
    }
} 