package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.request.AIRequest;

public class SecurityDecisionRequest extends AIRequest<SecurityDecisionContext> {

    public static final TemplateType TEMPLATE_TYPE = new TemplateType("SecurityDecisionStandard");
    public static final DiagnosisType DIAGNOSIS_TYPE = new DiagnosisType("SecurityDecision");

    public SecurityDecisionRequest(SecurityDecisionContext context) {
        super(context, TEMPLATE_TYPE, DIAGNOSIS_TYPE);
    }
}
