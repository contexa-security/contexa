package io.contexa.contexacore.std.pipeline.processor;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;

public class SecurityDecisionResponseProcessor implements DomainResponseProcessor {

    @Override
    public boolean supports(String templateKey) {
        return SecurityDecisionRequest.TEMPLATE_TYPE.name().equals(templateKey);
    }

    @Override
    public boolean supportsType(Class<?> responseType) {
        return SecurityDecisionResponseLite.class.equals(responseType);
    }

    @Override
    public Object wrapResponse(Object parsedData, PipelineExecutionContext context) {
        if (parsedData instanceof SecurityDecisionResponse fullResponse) {
            return fullResponse;
        }
        if (!(parsedData instanceof SecurityDecisionResponseLite liteResponse)) {
            throw new IllegalArgumentException(
                    "Expected SecurityDecisionResponseLite but got: "
                            + (parsedData != null ? parsedData.getClass().getName() : "null"));
        }
        return SecurityDecisionResponse.fromLite(liteResponse);
    }

    @Override
    public int getOrder() {
        return 15;
    }
}
