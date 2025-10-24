package io.contexa.contexacore.std.pipeline.processor;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;

/**
 * 도메인별 응답 후처리 인터페이스
 * 
 * AI가 생성한 핵심 데이터를 도메인별 응답 객체로 래핑하는 역할을 담당합니다.
 * 이를 통해 AI는 단순한 데이터만 생성하고, 메타데이터는 애플리케이션에서 관리합니다.
 * 
 * @since 1.0
 */
public interface DomainResponseProcessor {
    
    /**
     * 이 프로세서가 처리할 수 있는 템플릿 키인지 확인
     * 
     * @param templateKey 템플릿 키 (예: "riskAssessment", "policyGeneration")
     * @return 처리 가능 여부
     */
    boolean supports(String templateKey);
    
    /**
     * 이 프로세서가 처리할 수 있는 응답 타입인지 확인
     * 
     * @param responseType 파싱된 응답 객체의 클래스
     * @return 처리 가능 여부
     */
    boolean supportsType(Class<?> responseType);
    
    /**
     * 파싱된 AI 응답을 도메인별 응답 객체로 래핑
     * 
     * @param parsedData AI가 생성한 핵심 데이터 (예: TrustAssessment)
     * @param context 파이프라인 실행 컨텍스트 (requestId, 메타데이터 등 포함)
     * @return 도메인별 응답 객체 (예: RiskAssessmentResponse)
     */
    Object wrapResponse(Object parsedData, PipelineExecutionContext context);
    
    /**
     * 프로세서의 우선순위 (낮을수록 높은 우선순위)
     * 
     * @return 우선순위 값
     */
    default int getOrder() {
        return 0;
    }
}