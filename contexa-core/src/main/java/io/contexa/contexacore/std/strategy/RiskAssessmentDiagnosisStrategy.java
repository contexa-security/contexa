package io.contexa.contexacore.std.strategy;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.RiskAssessmentRequest;
import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.labs.risk.RiskAssessmentLab;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
public class RiskAssessmentDiagnosisStrategy extends AbstractAIStrategy<RiskAssessmentContext, RiskAssessmentResponse> {

    @Autowired
    public RiskAssessmentDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
    }

    @Override
    public DiagnosisType getSupportedType() {
        return new DiagnosisType("RiskAssessment");
    }

    @Override
    public int getPriority() {
        return 10; 
    }

    @Override
    public boolean supportsStreaming() {
        return true; 
    }

    @Override
    protected void validateRequest(AIRequest<RiskAssessmentContext> request) throws DiagnosisException {

        if (!(request instanceof RiskAssessmentRequest)) {
            throw new DiagnosisException("INVALID_REQUEST_TYPE", "TYPE_MISMATCH",
                    "Expected RiskAssessmentRequest, got: " + request.getClass().getSimpleName());
        }

        RiskAssessmentRequest riskRequest = (RiskAssessmentRequest) request;

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
    protected Object convertLabRequest(AIRequest<RiskAssessmentContext> request) {
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
