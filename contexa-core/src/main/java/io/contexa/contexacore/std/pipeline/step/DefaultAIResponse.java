package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacommon.domain.request.AIResponse;

public class DefaultAIResponse extends AIResponse {
    private final Object data;

    public DefaultAIResponse(String requestId, Object data) {
        super(requestId, ExecutionStatus.SUCCESS);
        this.data = data;
    }

    @Override
    public Object getData() {
        return data;
    }

    @Override
    public String getResponseType() {
        return "DEFAULT_STRING_RESPONSE";
    }
}
