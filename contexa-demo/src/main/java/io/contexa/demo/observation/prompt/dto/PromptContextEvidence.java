package io.contexa.demo.observation.prompt.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.List;

public record PromptContextEvidence(
        String sourceBoundary,
        Instant projectedAt,
        SessionHistoryEvidence session,
        BaselineHistoryEvidence baseline,
        String retrievalOutcome,
        Integer attachedReferenceCount,
        List<PromptReferenceEvidence> references,
        boolean referencesTruncated,
        @JsonInclude(JsonInclude.Include.NON_NULL) RagSearchEvidence retrieval) {

    public PromptContextEvidence {
        references = List.copyOf(references);
    }
}
