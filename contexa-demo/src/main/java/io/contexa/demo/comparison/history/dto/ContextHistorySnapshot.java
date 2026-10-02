package io.contexa.demo.comparison.history.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.demo.observation.learning.dto.BaselineValueSnapshot;
import java.time.Instant;
import java.util.Map;

public record ContextHistorySnapshot(
        String state,
        Instant readStartedAt,
        Instant readFinishedAt,
        String scopeSource,
        String sessionSha256,
        String tenantSha256,
        String organizationSha256,
        String organizationState,
        BaselineValueSnapshot organizationBaseline,
        SessionClockSnapshot sessionClock,
        Map<String, HistorySequenceFingerprint> sequences,
        String consistencyBoundary,
        @JsonInclude(JsonInclude.Include.NON_NULL) RoleScopeHistorySnapshot roleScopeHistory
) {
}
