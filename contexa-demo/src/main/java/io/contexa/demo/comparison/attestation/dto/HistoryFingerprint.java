package io.contexa.demo.comparison.attestation.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.demo.comparison.history.dto.ContextHistorySnapshot;
import java.time.Instant;

public record HistoryFingerprint(
        String state,
        String source,
        String baselineSha256,
        Long updates,
        Instant lastUpdated,
        String analysisSha256,
        String priorRequestId,
        String priorAction,
        @JsonInclude(JsonInclude.Include.NON_NULL) ContextHistorySnapshot contextHistory
) {
}
