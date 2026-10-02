package io.contexa.demo.comparison.preparation.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.demo.work.shared.dto.WorkText;

public record ArmDocumentFingerprint(
        String arm,
        String state,
        String documentId,
        Integer version,
        String projectId,
        String documentSha256,
        String bilingualContentSha256,
        @JsonInclude(JsonInclude.Include.NON_NULL) WorkText title
) implements ComparisonResourceFingerprint {

    @Override
    @JsonIgnore
    public String resourceId() {
        return documentId;
    }

    @Override
    @JsonIgnore
    public String sourceSha256() {
        return documentSha256;
    }
}
