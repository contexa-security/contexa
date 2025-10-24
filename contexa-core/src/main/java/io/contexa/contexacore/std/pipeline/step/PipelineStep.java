package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import reactor.core.publisher.Mono;

/**
 * 범용 파이프라인 단계 인터페이스
 * 
 * SRP: 각 단계는 하나의 책임만 가짐
 * OCP: 새로운 단계 추가 시 기존 코드 수정 불필요
 * 
 * 사용법:
 * 1. 각 파이프라인 단계를 독립적인 클래스로 구현
 * 2. execute() 메서드에서 해당 단계의 로직만 처리
 * 3. 결과를 context에 저장하여 다음 단계로 전달
 */
public interface PipelineStep {
    
    /**
     * 파이프라인 단계 실행
     * 
     * @param request AI 요청 객체
     * @param context 파이프라인 실행 컨텍스트 (단계간 데이터 공유)
     * @return 단계 실행 결과
     */
    <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context);
    
    /**
     * 단계 이름 반환 (디버깅 및 로깅용)
     */
    String getStepName();
    
    /**
     * 단계 실행 전 검증
     * 
     * @param request AI 요청 객체
     * @return 실행 가능 여부
     */
    default <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return request != null;
    }
    
    /**
     * 단계 실행 순서 (낮은 값이 먼저 실행)
     */
    default int getOrder() {
        return 100;
    }
} 