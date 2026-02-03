package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexacommon.domain.request.AIRequest;

public class PolicyGenerationRequest extends AIRequest<PolicyContext> {

    private PolicyGenerationItem.AvailableItems availableItems;

    public PolicyGenerationRequest(PolicyContext context, TemplateType templateType, DiagnosisType diagnosisType) {
        super(context, templateType, diagnosisType);
    }

    public PolicyGenerationItem.AvailableItems getAvailableItems() {
        return availableItems;
    }

    public void setAvailableItems(PolicyGenerationItem.AvailableItems availableItems) {
        this.availableItems = availableItems;
    }
}
