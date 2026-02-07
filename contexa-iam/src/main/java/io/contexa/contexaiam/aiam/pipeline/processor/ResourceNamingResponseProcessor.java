package io.contexa.contexaiam.aiam.pipeline.processor;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.processor.DomainResponseProcessor;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingSuggestionResponse;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@Slf4j
public class ResourceNamingResponseProcessor implements DomainResponseProcessor {

    @Override
    public boolean supports(String templateKey) {
        return "ResourceNaming".equals(templateKey);
    }

    @Override
    public boolean supportsType(Class<?> responseType) {
        return false;
    }

    @Override
    @SuppressWarnings("unchecked")
    public Object wrapResponse(Object parsedData, PipelineExecutionContext context) {
        if (!(parsedData instanceof Map)) {
            throw new IllegalArgumentException(
                    "Expected Map but got: " + (parsedData != null ? parsedData.getClass().getName() : "null")
            );
        }
        Map<String, Object> mapResponse = (Map<String, Object>) parsedData;
        return ResourceNamingSuggestionResponse.fromMap(mapResponse);
    }

    @Override
    public int getOrder() {
        return 20;
    }
}
