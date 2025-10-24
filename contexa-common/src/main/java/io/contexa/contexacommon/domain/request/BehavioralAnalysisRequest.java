package io.contexa.contexacommon.domain.request;


import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import io.contexa.contexacommon.enums.DiagnosisType;

public class BehavioralAnalysisRequest extends IAMRequest<BehavioralAnalysisContext> {

    private static final DiagnosisType DIAGNOSIS_TYPE = DiagnosisType.BEHAVIORAL_ANALYSIS;

    public BehavioralAnalysisRequest(BehavioralAnalysisContext context, String operation) {
        super(context, operation, RequestPriority.HIGH, RequestType.STANDARD);
        this.withDiagnosisType(DIAGNOSIS_TYPE);
    }

    public BehavioralAnalysisRequest(BehavioralAnalysisContext context, String operation, String sessionId) {
        this(context, operation);
    }

    public static BehavioralAnalysisRequest create(BehavioralAnalysisContext context, String operation) {
        return new BehavioralAnalysisRequest(context, operation);
    }

    public static BehavioralAnalysisRequest create(BehavioralAnalysisContext context, String operation, String sessionId) {
        return new BehavioralAnalysisRequest(context, operation, sessionId);
    }
}
