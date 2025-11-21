package io.contexa.contexacore.std.strategy;

import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.labs.behavior.BehavioralAnalysisLab;
import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.BehavioralAnalysisRequest;
import io.contexa.contexacommon.domain.response.BehavioralAnalysisResponse;
import io.contexa.contexacommon.enums.DiagnosisType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * '사용자 행동 분석' 진단 전략.
 * RiskAssessmentDiagnosisStrategy의 구조와 로직을 100% 준수하여 구현합니다.
 */
@Slf4j
public class BehavioralAnalysisDiagnosisStrategy extends AbstractAIStrategy<BehavioralAnalysisContext, BehavioralAnalysisResponse> {

    @Autowired
    public BehavioralAnalysisDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
    }

    @Override
    public DiagnosisType getSupportedType() {
        return DiagnosisType.BEHAVIORAL_ANALYSIS;
    }

    @Override
    public int getPriority() {
        return 1;
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    @Override
    protected void validateRequest(AIRequest<BehavioralAnalysisContext> request) throws DiagnosisException {
        if (request.getContext() == null) {
            throw new DiagnosisException("MISSING_CONTEXT", "CONTEXT_NULL", "BehavioralAnalysisContext is required.");
        }
        if (request.getContext().getUserId() == null || request.getContext().getUserId().isEmpty()) {
            throw new DiagnosisException("MISSING_USER_ID", "USER_ID_NULL", "User ID is required for behavioral analysis.");
        }
    }

    @Override
    protected Class<?> getLabType() {
        return BehavioralAnalysisLab.class;
    }

    @Override
    protected Object buildLabRequest(AIRequest<BehavioralAnalysisContext> request) {
        return request;
    }

    @Override
    protected BehavioralAnalysisResponse processLabExecution(Object lab, Object labRequest, AIRequest<BehavioralAnalysisContext> request) throws Exception {
        AILab<BehavioralAnalysisRequest, BehavioralAnalysisResponse> behaviorLab = (BehavioralAnalysisLab) lab;
        BehavioralAnalysisRequest behaviorRequest = (BehavioralAnalysisRequest)labRequest;
        return behaviorLab.process(behaviorRequest);
    }

    @Override
    protected Mono<BehavioralAnalysisResponse> processLabExecutionAsync(Object lab, Object labRequest, AIRequest<BehavioralAnalysisContext> originRequest) {
        AILab<BehavioralAnalysisRequest, BehavioralAnalysisResponse> behaviorLab = (BehavioralAnalysisLab) lab;
        BehavioralAnalysisRequest behaviorRequest = (BehavioralAnalysisRequest)labRequest;
        return behaviorLab.processAsync(behaviorRequest);
    }

    @Override
    protected Flux<String> processLabExecutionStream(Object lab, Object labRequest, AIRequest<BehavioralAnalysisContext> request) {
        AILab<BehavioralAnalysisRequest, BehavioralAnalysisResponse> behaviorLab = (BehavioralAnalysisLab) lab;
        BehavioralAnalysisRequest behaviorRequest = (BehavioralAnalysisRequest)labRequest;
        return behaviorLab.processStream(behaviorRequest);
    }
}

