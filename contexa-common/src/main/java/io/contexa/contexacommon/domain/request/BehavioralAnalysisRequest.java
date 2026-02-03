package io.contexa.contexacommon.domain.request;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;

public class BehavioralAnalysisRequest extends AIRequest<BehavioralAnalysisContext> {

    public BehavioralAnalysisRequest(BehavioralAnalysisContext context, TemplateType templateType, DiagnosisType diagnosisType) {
        super(context, templateType, diagnosisType);
    }

    public static BehavioralAnalysisRequest create(BehavioralAnalysisContext context, TemplateType templateType, DiagnosisType diagnosisType) {
        return new BehavioralAnalysisRequest(context, templateType, diagnosisType);
    }

}
