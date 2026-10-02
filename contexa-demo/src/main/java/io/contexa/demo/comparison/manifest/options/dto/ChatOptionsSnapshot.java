package io.contexa.demo.comparison.manifest.options.dto;

import java.util.List;
import java.util.Map;

public record ChatOptionsSnapshot(
        String state,
        String sourceClass,
        Map<String, Object> values,
        Map<String, String> contentSha256,
        List<String> unsetOptions,
        List<String> unsupportedOptions,
        List<String> excludedTransportOptions
) {
}
