package io.contexa.contexacore.std.pipeline.analyzer;

import lombok.Builder;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;


@Getter
@Builder
public class RequestCharacteristics {

    
    private final double complexity;

    
    private final boolean requiresContextRetrieval;

    
    private final boolean requiresFastResponse;

    
    private final boolean requiresHighAccuracy;

    
    private final int estimatedDataVolume;

    
    private final String requestType;

    
    @Builder.Default
    private final Map<String, Object> metadata = new HashMap<>();

    
    public Map<String, Object> toContextMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("request_complexity", complexity);
        map.put("requires_context_retrieval", requiresContextRetrieval);
        map.put("requires_fast_response", requiresFastResponse);
        map.put("requires_high_accuracy", requiresHighAccuracy);
        map.put("estimated_data_volume", estimatedDataVolume);
        map.put("request_type", requestType);
        map.putAll(metadata);
        return map;
    }

    @Override
    public String toString() {
        return String.format(
            "RequestCharacteristics[complexity=%.2f, contextRetrieval=%s, fastResponse=%s, highAccuracy=%s, type=%s]",
            complexity, requiresContextRetrieval, requiresFastResponse, requiresHighAccuracy, requestType
        );
    }
}
