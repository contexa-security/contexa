package io.contexa.demo.comparison.manifest.dto;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;

public record NativeConfigurationSnapshot(String state, String source, List<NativeModelConfiguration> models,
        Map<String, JsonNode> policies, String configurationSha256, List<String> boundaries) {
}
