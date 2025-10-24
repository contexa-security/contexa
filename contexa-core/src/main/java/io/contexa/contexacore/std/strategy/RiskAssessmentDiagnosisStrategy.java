package io.contexa.contexacore.std.strategy;

import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.labs.risk.RiskAssessmentLab;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.RiskAssessmentRequest;
import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import io.contexa.contexacommon.enums.DiagnosisType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * 위험 평가 진단 전략 (리팩토링 버전)
 *
 * 기존 RiskAssessmentDiagnosisStrategy의 모든 기능을 유지하면서
 * 새로운 추상 클래스 구조를 활용하여 중복 코드 제거
 *
 * LabAccessor를 통한 타입 안전한 동적 Lab 조회
 * 스트리밍 지원
 * DiagnosisType.RISK_ASSESSMENT 처리
 */
@Slf4j
@Component("riskAssessmentDiagnosisStrategyRefactored")
public class RiskAssessmentDiagnosisStrategy extends AbstractAIStrategy<RiskAssessmentContext, RiskAssessmentResponse> {

    @Autowired
    public RiskAssessmentDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
    }

    @Override
    public DiagnosisType getSupportedType() {
        return DiagnosisType.RISK_ASSESSMENT;
    }

    @Override
    public int getPriority() {
        return 10; // 높은 우선순위 (기존과 동일)
    }

    @Override
    public boolean supportsStreaming() {
        return true; // 스트리밍 지원 (기존과 동일)
    }

    @Override
    protected void validateRequest(AIRequest<RiskAssessmentContext> request) throws DiagnosisException {
        // 기존 검증 로직 그대로 유지

        // 1. 요청 타입 검증
        if (!(request instanceof RiskAssessmentRequest)) {
            throw new DiagnosisException("INVALID_REQUEST_TYPE", "TYPE_MISMATCH",
                    "Expected RiskAssessmentRequest, got: " + request.getClass().getSimpleName());
        }

        RiskAssessmentRequest riskRequest = (RiskAssessmentRequest) request;

        // 2. 컨텍스트 검증
        RiskAssessmentContext context = riskRequest.getContext();
        if (context == null) {
            throw new DiagnosisException("MISSING_CONTEXT", "CONTEXT_NULL",
                    "RiskAssessmentContext is required for risk assessment");
        }
    }

    @Override
    protected Class<?> getLabType() {
        return RiskAssessmentLab.class;
    }

    @Override
    protected Object buildLabRequest(AIRequest<RiskAssessmentContext> request) {
        return request;
    }

    @Override
    protected RiskAssessmentResponse processLabExecution(Object lab, Object labRequest, AIRequest<RiskAssessmentContext> request) throws Exception {
        AILab<RiskAssessmentRequest, RiskAssessmentResponse> riskAssessmentLab = (RiskAssessmentLab) lab;
        RiskAssessmentResponse assessment = riskAssessmentLab.process((RiskAssessmentRequest) request);
        if (assessment == null) {
            throw new DiagnosisException("NULL_RESULT", "ASSESSMENT_NULL",
                    "Risk assessment returned null result");
        }

        log.info("위험 평가 진단 전략 실행 완료: {}", assessment.getRequestId());

        return assessment;
    }

    @Override
    protected Mono<RiskAssessmentResponse> processLabExecutionAsync(Object lab, Object labRequest, AIRequest<RiskAssessmentContext> originRequest) {
        AILab<RiskAssessmentRequest, RiskAssessmentResponse> riskAssessmentLab = (RiskAssessmentLab) lab;
        return riskAssessmentLab.processAsync((RiskAssessmentRequest) originRequest);
    }

    @Override
    protected Flux<String> processLabExecutionStream(Object lab, Object labRequest, AIRequest<RiskAssessmentContext> request) {

        try {
            AILab<RiskAssessmentRequest, RiskAssessmentResponse> riskAssessmentLab = (RiskAssessmentLab) lab;
            return riskAssessmentLab.processStream((RiskAssessmentRequest) request);

        } catch (Exception e) {
            log.error("Streaming risk assessment failed", e);
            return Flux.error(new DiagnosisException("STREAMING_FAILED", "PROCESSING_ERROR",
                    "Streaming risk assessment failed: " + e.getMessage(), e));
        }
    }

    // ==================== 커스텀 에러 메시지 (선택적 오버라이드) ====================

    @Override
    protected String getExecutionErrorMessage() {
        return "위험 평가 진단 중 예상치 못한 오류 발생: ";
    }

    @Override
    protected String getAsyncExecutionErrorMessage() {
        return "비동기 위험 평가 중 예상치 못한 오류 발생: ";
    }

    @Override
    protected String getStreamExecutionErrorMessage() {
        return "스트리밍 위험 평가 중 예상치 못한 오류 발생: ";
    }
}
