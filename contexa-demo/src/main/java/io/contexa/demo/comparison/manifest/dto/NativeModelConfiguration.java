package io.contexa.demo.comparison.manifest.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.demo.comparison.manifest.options.dto.ChatOptionsSnapshot;
import java.util.Map;

public record NativeModelConfiguration(String runtimeId, String provider, String modelId, String type,
        boolean primary, String source, String state, Map<String, Object> defaultOptions,
        @JsonInclude(JsonInclude.Include.NON_NULL) ChatOptionsSnapshot optionsSnapshot) {
}
