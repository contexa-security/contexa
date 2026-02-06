package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacommon.domain.request.AIResponse;

public class DefaultAIResponse extends AIResponse {
    private final Object data;

    public DefaultAIResponse(Object data) {
        this.data = data;
    }
}
