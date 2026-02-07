package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;

public class ConditionTemplateGenerationRequest extends AIRequest<ConditionTemplateContext> {

    public ConditionTemplateGenerationRequest(ConditionTemplateContext context) {
        super(context,
              new TemplateType("ConditionTemplate"),
              new DiagnosisType("ConditionTemplate"));
    }
}
