package io.contexa.contexacommon.domain.request;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.enums.RequestPriority;
import io.contexa.contexacommon.enums.RequestType;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class RiskAssessmentRequest extends AIRequest<RiskAssessmentContext> {
    
    private String sessionId;
    private String nodeId;
    private String userId;
    private String resourceId;
    private String actionType;
    private boolean enableHistoryAnalysis = true;
    private boolean enableBehaviorAnalysis = true;
    private int maxHistoryRecords = 5;
    
    public RiskAssessmentRequest(RiskAssessmentContext context, TemplateType templateType, DiagnosisType diagnosisType) {
        super(context, templateType, diagnosisType);
    }

    public static RiskAssessmentRequest create(RiskAssessmentContext context, TemplateType templateType, DiagnosisType diagnosisType) {
        return new RiskAssessmentRequest(context, templateType, diagnosisType);
    }
}