package io.contexa.demo.observation.prompt.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

public record PromptReferenceEvidence(
        String documentIdSha256,
        String contentSha256,
        Double similarity,
        @JsonInclude(JsonInclude.Include.NON_NULL) String nativeMetadataIdSha256,
        @JsonInclude(JsonInclude.Include.NON_NULL) String artifactIdSha256) {
}
